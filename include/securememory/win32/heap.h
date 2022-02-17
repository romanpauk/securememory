#include <cassert>
#include <stdexcept>

namespace securememory::win32
{
    class heap
    {
        class exception : public std::exception
        {
        public:
            exception(const char* function, DWORD last_error)
                : last_error_(last_error)
                , function_(function)
            {}

            const char* what() const override { return function_; }
            DWORD get_last_error() const { return last_error_; }

        private:
            DWORD last_error_;
            const char* function_;
        };

        struct heap_deleter
        {
            void operator()(HANDLE handle)
            {
                if (!HeapDestroy(handle))
                {
                    throw exception("HeapDestroy", GetLastError());
                }
            }

            typedef HANDLE pointer;
        };
       
    public:
        heap(size_t size)
            : heap_(HeapCreate(0, size, size), heap_deleter())
            , base_address_()
            , size_(size)
        {
            base_address_ = init_base_address();
                    
            // Resize the working set according to size requested.
            SIZE_T dwMin, dwMax;
            if (!GetProcessWorkingSetSize(GetCurrentProcess(), &dwMin, &dwMax))
            {
                throw exception("GetProcessWorkingSetSize", GetLastError());
            }

            if (!SetProcessWorkingSetSize(GetCurrentProcess(), dwMin + size_ + 0, dwMax + size_ + 0))
            {
                throw exception("SetProcessWorkingSetSize", GetLastError());
            }

            // Lock the heap pages
            if (VirtualLock(base_address_, size_) == FALSE)
            {                
                throw exception("VirtualLock", GetLastError());
            }
        }

        ~heap()
        {
            assert(heap_ != NULL);
            // TODO: zero commited allocations before unlocking
           
            // No need to unlock the pages as HeapDestroy will do it.
        }

        void* allocate(std::size_t size)
        {
            assert(heap_ != NULL);
            return HeapAlloc(heap_.get(), 0, size);
        }

        void deallocate(void* ptr, std::size_t size)
        {
            assert(heap_ != NULL);

            SecureZeroMemory(ptr, size);
            
            if (HeapFree(heap_.get(), 0, ptr) == FALSE)
            {
                throw exception("HeapFree", GetLastError());
            }
        }

        uintptr_t base_address() const
        {
            return reinterpret_cast< uintptr_t >(base_address_);
        }

        // Used in allocator::max_size(), yet this is slightly bigger than max size due to heap overhead.
        std::size_t size() const
        {
            return size_;
        }

    private:
        // Needs to be called before any allocations are made.
        LPVOID init_base_address()
        {
            LPVOID base = NULL;
            PROCESS_HEAP_ENTRY entry = { 0 };
            entry.wFlags = PROCESS_HEAP_REGION;
                        
            while (HeapWalk(heap_.get(), &entry) != FALSE)
            {
                if ((entry.wFlags & PROCESS_HEAP_REGION) != 0)
                {
                    assert(entry.Region.dwUnCommittedSize == 0);
                    assert(entry.Region.dwCommittedSize >= size_);
                    assert(base_address_ == 0);
                    
                    base = entry.lpData;
                    
                #if !defined(_DEBUG)
                    break;
                #endif
                }
            }

            auto error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
            {
                throw exception("HeapWalk", error);
            }

            assert(base != NULL);
            return base;
        }

        std::unique_ptr< HANDLE, heap_deleter > heap_;
        LPVOID base_address_;
        std::size_t size_;
    };
}