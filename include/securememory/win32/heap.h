#include <cassert>
#include <stdexcept>
#include <mutex>

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
        heap(std::size_t reserve)
            : heap_(HeapCreate(0, get_page_size(), reserve), heap_deleter())
            , base_address_()
            , size_(reserve)
            , heap_page_refs_(std::max(std::size_t(1), reserve / get_page_size()))
        {
            // TODO: get heap size properly by walking heap
            base_address_ = init_base_address();
                    
            // TODO:
            // Resize the working set according to heap size.
            SIZE_T dwMin, dwMax;
            if (!GetProcessWorkingSetSize(GetCurrentProcess(), &dwMin, &dwMax))
            {
                throw exception("GetProcessWorkingSetSize", GetLastError());
            }

            if (!SetProcessWorkingSetSize(GetCurrentProcess(), dwMin + reserve + 0, dwMax + reserve + 0))
            {
                throw exception("SetProcessWorkingSetSize", GetLastError());
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

            std::lock_guard< std::mutex > lock(mutex_);

            void* ptr = HeapAlloc(heap_.get(), 0, size);
            if (ptr)
            {
                uintptr_t pagemask = ~(get_page_size() - 1);
                uintptr_t address = reinterpret_cast<uintptr_t>(ptr) & pagemask;
                uintptr_t base = base_address() & pagemask;

                std::size_t pages = std::max(std::size_t(1), size / get_page_size());
                for (size_t i = 0; i < pages; ++i, address += get_page_size())
                {
                    uintptr_t index = (address - base) / get_page_size();
                    if (heap_page_refs_[index] == 0)
                    {                        
                        if (VirtualLock(reinterpret_cast<LPVOID>(address), get_page_size()))
                        {
                            ++heap_page_refs_[index];
                        }
                        else
                        {
                            deallocate(ptr, size);

                            // TODO: not sure about the exception
                            throw exception("VirtualLock", GetLastError());
                        }                       
                    }
                }
            }

            return ptr;
        }

        void deallocate(void* ptr, std::size_t size)
        {
            assert(heap_ != NULL);

            if (ptr)
            {
                SecureZeroMemory(ptr, size);

                uintptr_t pagemask = ~(get_page_size() - 1);
                uintptr_t address = reinterpret_cast<uintptr_t>(ptr) & pagemask;
                uintptr_t base = base_address() & pagemask;

                std::lock_guard< std::mutex > lock(mutex_);

                std::size_t pages = std::max(std::size_t(1), size / get_page_size());
                for (size_t i = 0; i < pages; ++i, address += get_page_size())
                {
                    uintptr_t index = (address - base) / get_page_size();
                    if (heap_page_refs_[index] == 1)
                    {
                        if (VirtualUnlock(reinterpret_cast<LPVOID>(address), get_page_size()))
                        {
                            --heap_page_refs_[index];
                        }
                        else
                        {
                            // TODO: not sure about the exception. 
                            // But the fact that we failed to unlock the page may be serious.
                            // This code has issues with multiple exceptions.
                            throw exception("VirtualUnlock", GetLastError());
                        }                       
                    }
                }

                // TODO: on scope exit, free
                if (HeapFree(heap_.get(), 0, ptr) == FALSE)
                {
                    throw exception("HeapFree", GetLastError());
                }
            }
        }

        uintptr_t base_address() const
        {
            return reinterpret_cast< uintptr_t >(base_address_);
        }
                
        std::size_t locked_size() const
        {
            std::lock_guard< std::mutex > lock(mutex_);

            std::size_t count = 0;
            for (auto& ref : heap_page_refs_)
            {
                count += ref > 0;
            }

            return count * get_page_size();
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
                    assert(entry.Region.dwUnCommittedSize + entry.Region.dwCommittedSize >= size_);
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

        static uintptr_t get_page_size()
        {
            static uintptr_t page_size = []() { SYSTEM_INFO si; GetSystemInfo(&si); return si.dwPageSize; }();
            return page_size;
        }
        
        // TODO: this mutex is on very defensive side. It should be possible to use atomic refcounts at least.
        mutable std::mutex mutex_;
        std::unique_ptr< HANDLE, heap_deleter > heap_;        
        std::vector< uint32_t > heap_page_refs_;

        LPVOID base_address_;
        std::size_t size_;
    };
}