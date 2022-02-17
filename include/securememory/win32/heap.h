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
            , allocated_()
        {            
            // The code here needs to work with heap region that was created based on 'reserve' argument.
            // But the region will most probably be bigger.

            std::tie(base_address_, size_) = get_heap_region(heap_.get(), reserve);

            // Resize the working set according to the region size.
            SIZE_T dwMin, dwMax;
            if (!GetProcessWorkingSetSize(GetCurrentProcess(), &dwMin, &dwMax))
            {
                throw exception("GetProcessWorkingSetSize", GetLastError());
            }

            if (!SetProcessWorkingSetSize(GetCurrentProcess(), dwMin + size_ + 0, dwMax + size_ + 0))
            {
                throw exception("SetProcessWorkingSetSize", GetLastError());
            }

            // Allocate reference count for each page in the region
            heap_page_refs_.resize(std::max(std::size_t(1), size_ / get_page_size()));
        }

        ~heap()
        {
            assert(heap_ != NULL);
            
            // Clear remaining allocations before unlocking
            std::size_t cleared = 0;
            PROCESS_HEAP_ENTRY entry = { 0 };
            while (HeapWalk(heap_.get(), &entry) != FALSE)
            {
                if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
                {
                    SecureZeroMemory(entry.lpData, entry.cbData);
                    cleared += entry.cbData;
                }
            }

            // TODO:
            // Everything what was allocated should be cleared
            // assert(allocated_ - cleared == 0);

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
                            // We failed to lock the page so we don't have a secure allocation, 
                            // that is for sure. Clean what we can and return nullptr.
                            deallocate(lock, ptr, size);                            
                            return nullptr;
                        }                       
                    }
                }

                allocated_ += size;
            }

            return ptr;
        }

        void deallocate(void* ptr, std::size_t size)
        {
            if (ptr)
            {
                std::lock_guard< std::mutex > lock(mutex_);

                // HeapSize is usually larger than what allocate/deallocate request. 
                // Lets assume clients are not writing secure data over requested size.           
                assert(HeapSize(heap_.get(), 0, ptr) >= size);
                               
                // Bigger size is what we will clear and unlock.
                SecureZeroMemory(ptr, size);
                deallocate(lock, ptr, size);
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
        void deallocate(const std::lock_guard< std::mutex >&, void* ptr, std::size_t size)
        {
            assert(heap_ != NULL);

            if (HeapFree(heap_.get(), 0, ptr) == FALSE)
            {
                // Perhaps we failed to free the allocation from the heap, but it was wiped out
                // so technically deallocated and the pages can go out of lock.
                assert(false);
            }
            else
            {
                allocated_ -= size;
            }

            uintptr_t pagemask = ~(get_page_size() - 1);
            uintptr_t address = reinterpret_cast<uintptr_t>(ptr) & pagemask;
            uintptr_t base = base_address() & pagemask;

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
                        // The fact that we failed to unlock a page may be serious.
                        assert(false);
                    }
                }
            }
        }

        // Needs to be called before any allocations are made.
        static std::pair< LPVOID, std::size_t > get_heap_region(HANDLE handle, std::size_t reserve)
        {
            LPVOID base = NULL;
            std::size_t size = 0;
            PROCESS_HEAP_ENTRY entry = { 0 };            
            while (HeapWalk(handle, &entry) != FALSE)
            {
                if ((entry.wFlags & PROCESS_HEAP_REGION) != 0)
                {   
                    assert(entry.Region.dwUnCommittedSize + entry.Region.dwCommittedSize >= reserve);
                    size = entry.Region.dwUnCommittedSize + entry.Region.dwCommittedSize;
                                        
                    assert(base == 0);
                    base = entry.lpData;
                    
                    // Walk it till the end to get proper error code
                }
            }

            // If this logic failed, it is serious issue as we are not sure what pages should we protect.

            auto error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
            {
                
                throw exception("HeapWalk", error);
            }

            assert(base != NULL);
            assert(size >= reserve);
            return { base, size };
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
        std::size_t allocated_;
    };
}