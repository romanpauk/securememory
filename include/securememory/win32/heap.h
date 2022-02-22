//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <cassert>
#include <stdexcept>
#include <mutex>

// #define HEAP_VERIFY

#if !defined(HEAP_VERIFY)
#if defined(_DEBUG)
#define HEAP_VERIFY
#endif
#endif

#if defined(HEAP_VERIFY)
#define HEAP_ABORT(message) do { std::cerr << __FILE__ << ":" << __LINE__ << ": " << (message) << std::endl; std::abort(); } while(0)
#define HEAP_ASSERT(...) do { if(!(__VA_ARGS__)) { HEAP_ABORT(#__VA_ARGS__); } } while(0)
#include <psapi.h>
#else
#define HEAP_ASSERT(...)
#endif

namespace securememory::win32
{
    class heap
    {
        class exception : public std::exception
        {
        public:
            exception(const char* function, DWORD last_error = GetLastError())
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
        static constexpr std::size_t alignment = MEMORY_ALLOCATION_ALIGNMENT;

        heap(std::size_t reserve)
            : allocated_()
        {
            if (reserve == 0)
            {
                throw std::runtime_error("reserve == 0");
            }

            HANDLE handle = HeapCreate(0, get_page_size(), reserve);
            if (!handle)
            {
                throw exception("HeapCreate");
            }

            // The code with heap region that was created based on reserve argument.
            // The region will most probably be bigger than what reserve requested.

            std::tie(base_address_, size_) = get_heap_region(handle, reserve);

            // Resize the working set according to the region size.
            SIZE_T dwMin, dwMax;
            if (!GetProcessWorkingSetSize(GetCurrentProcess(), &dwMin, &dwMax))
            {
                throw exception("GetProcessWorkingSetSize");
            }

            if (!SetProcessWorkingSetSize(GetCurrentProcess(), dwMin + size_ + 0, dwMax + size_ + 0))
            {
                throw exception("SetProcessWorkingSetSize");
            }

            // Allocate reference counts and locks for each page in the region
            heap_pages_.reset(new heap_page[(size_ + get_page_size()) / get_page_size()]);
            heap_.reset(handle);
        }

        ~heap()
        {
            HEAP_ASSERT(heap_ != NULL);

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

            // Everything that was allocated should be cleared by now
            HEAP_ASSERT(allocated_ - cleared == 0);

            // TODO: this needs to be done more carefully from HeapWalk as the pages could be decommited.
            // HEAP_ASSERT(verify_locked(get_base_address(), (size_ + get_page_size()) / get_page_size(), false));

            // No need to unlock the pages as HeapDestroy will do it.
        }

        void* allocate(std::size_t size)
        {
            HEAP_ASSERT(heap_ != NULL);

            void* ptr = HeapAlloc(heap_.get(), 0, size);
            if (ptr)
            {
                if (lock_address_range(ptr, size))
                {
                    // Allocated memory is properly locked in memory, return it.
                    allocated_ += size;
                    return ptr;
                }
                else
                {
                    // The memory cannot be locked, fail the allocation.
                    if (HeapFree(heap_.get(), 0, ptr) == FALSE)
                    {
                        HEAP_ASSERT(false);
                    }
                }
            }

            return nullptr;
        }

        void deallocate(void* ptr, std::size_t size)
        {
            HEAP_ASSERT(heap_ != NULL);

            if (ptr)
            {
                // Lets assume clients are not writing secure data over requested size.
                HEAP_ASSERT(HeapSize(heap_.get(), 0, ptr) == size);

                SecureZeroMemory(ptr, size);

                // Unlock pages before calling HeapFree as that may implicitly unlock them.
                unlock_address_range(ptr, size);

                if (HeapFree(heap_.get(), 0, ptr) == FALSE)
                {
                    // Perhaps we failed to free the allocation from the heap, but it was wiped out
                    // so technically deallocated and the pages can go out of memory.
                    HEAP_ASSERT(false);
                }
                else
                {
                    HEAP_ASSERT(allocated_ >= size);
                    allocated_ -= size;
                }
            }
        }

        uintptr_t get_base_address() const
        {
            return base_address_;
        }

        // TODO: this does not report correct number as not every page is counted because of how ranges are tracked.
        std::size_t get_locked_size() const
        {
            std::size_t count = 0;
            for (std::size_t i = 0; i < get_pages(size_); ++i)
            {
                count += heap_pages_[i].refs > 0;
            }

            return count * get_page_size();
        }

        static uintptr_t get_page_size()
        {
            static const uintptr_t page_size = []() { SYSTEM_INFO si; GetSystemInfo(&si); return si.dwPageSize; }();
            return page_size;
        }

        static uintptr_t get_page_mask()
        {
            static const uintptr_t page_mask = ~(get_page_size() - 1);
            return page_mask;
        }

        static std::size_t get_pages(std::size_t size)
        {
            return (size + get_page_size() - 1) / get_page_size();
        }

    private:
        // If page needs to be locked in the memory, lock the mutex and return true
        // If page is already in the memory increment the refcount and return false
        bool acquire_page(uintptr_t address)
        {
            uintptr_t base = get_base_address();
            uintptr_t index = (address - base) / get_page_size();

            do
            {
                // Check if count is 0 and page needs locking.
                auto count = heap_pages_[index].refs.load(std::memory_order_relaxed);
                if (count == 0)
                {
                    // Get exclusive access to the page
                    heap_pages_[index].lock.lock();

                    // Check that it is still 0
                    if (heap_pages_[index].refs.load(std::memory_order_acquire) == 0)
                    {
                        // The refcount should be incremented after the page is locked in the memory.
                        // Return 'locked' page.
                        return true;
                    }

                    // The page got locked in the meantime
                    heap_pages_[index].refs.fetch_add(1, std::memory_order_release);
                    heap_pages_[index].lock.unlock();
                    break;
                }
                else if (heap_pages_[index].refs.compare_exchange_weak(count, count + 1, std::memory_order_release))
                {
                    // Use cas instead of fetch so we do not increment the refcount without locking.
                    break;
                }
            } while (true);

            return false;
        }

        // Called after page is locked in the memory. If lock was successful, refcount should be incremented.
        void unlock_page(uintptr_t address, bool increment)
        {
            uintptr_t base = get_base_address();
            uintptr_t index = (address - base) / get_page_size();

            if (increment)
            {
                heap_pages_[index].refs.fetch_add(1);
            }

            heap_pages_[index].lock.unlock();
        }

        // Returns true and keep the page locked in case it should be unlocked from the memory.
        // Returns false in case the refcount was decremented.
        bool release_page(uintptr_t address)
        {
            uintptr_t base = get_base_address();
            uintptr_t index = (address - base) / get_page_size();

            // Check if we went from 1 to 0
            if (heap_pages_[index].refs.fetch_sub(1, std::memory_order_release) == 1)
            {
                // Get exclusive access to the page
                heap_pages_[index].lock.lock();
                if (heap_pages_[index].refs.load(std::memory_order_acquire) == 0)
                {
                    // We really went to 0
                    return true;
                }

                // Someone incremented the refcount in the meantime.
                heap_pages_[index].lock.unlock();
            }

            return false;
        }

        //
        // Locking and unlocking works on whole ranges. It is enough to increment refcount on first
        // and on the last page of the range, as by getting the memory from heap, the allocation is exclusive.
        // Only first and last page of the range can be shared with some other allocation. This is minor
        // complication in unlock_address_range function where we need to watch for different sharing cases
        // while unlocking page from memory.
        //
        // Because we work only with first and last page and their address is known, hashtable can be used.
        // Resizable hashtable is needed to support unbounded heaps.
        //
        bool lock_address_range(void* ptr, std::size_t size)
        {
            const uintptr_t first = reinterpret_cast<uintptr_t>(ptr) & get_page_mask();
            const auto pages = get_pages(size);
            const uintptr_t last = first + (pages - 1) * get_page_size();

            bool lock[2] = {};

            // Get first page
            lock[0] = acquire_page(first);
            if (pages > 1)
            {
                // Get second page
                lock[1] = acquire_page(last);
            }

            // If either one of the pages should be locked, lock them both
            if (lock[0] || lock[1])
            {
                // It is possible to call VirtualLock multiple times for the same pages
                // (unfortunatelly not true for VirtualUnlock).
                bool result = VirtualLock(reinterpret_cast<LPVOID>(first), pages * get_page_size()) == TRUE;
                if(!result)
                {
                    HEAP_ASSERT(false);
                }

                // Either increment the refcounts, or clear the locks.
                if (lock[0])
                {
                    unlock_page(first, result);
                }

                if (lock[1])
                {
                    unlock_page(last, result);
                }

                if (!result)
                {
                    return result;
                }
            }

            HEAP_ASSERT(verify_refcounts(first, pages, false));
            HEAP_ASSERT(verify_locked(first, pages, true));
            return true;
        }

        void unlock_address_range(void* ptr, std::size_t size)
        {
            uintptr_t first = reinterpret_cast<uintptr_t>(ptr) & get_page_mask();
            const auto pages = get_pages(size);
            const uintptr_t last = first + (pages - 1) * get_page_size();

            HEAP_ASSERT(verify_refcounts(first, pages, false));
            HEAP_ASSERT(verify_locked(first, pages, true));

            bool lock[2] = {};
            // Get first page
            lock[0] = release_page(first);
            if (pages == 1)
            {
                if (lock[0] && !VirtualUnlock(reinterpret_cast<LPVOID>(first), pages * get_page_size()))
                {
                    HEAP_ASSERT(false);
                }
            }
            else
            {
                // Get last page
                lock[1] = release_page(last);

                // Deal with the cases when first or last pages are shared with other allocation. That means
                // They cannot be unlocked.

                if (lock[0] && lock[1] && !VirtualUnlock(reinterpret_cast<LPVOID>(first), pages * get_page_size())) // Whole range
                {
                    HEAP_ASSERT(false);
                }
                else if (lock[0] && !lock[1] && !VirtualUnlock(reinterpret_cast<LPVOID>(first), (pages - 1) * get_page_size())) // Whole range except last page
                {
                    HEAP_ASSERT(false);
                }
                else if (!lock[0] && lock[1] && !VirtualUnlock(reinterpret_cast<LPVOID>(first + get_page_size()), (pages - 1) * get_page_size())) // Whole range except first page
                {
                    HEAP_ASSERT(false);
                }
                else if (pages > 2 && !VirtualUnlock(reinterpret_cast<LPVOID>(first + get_page_size()), (pages - 2) * get_page_size())) // Whole range except first and last
                {
                    HEAP_ASSERT(false);
                }
                else
                {
                    // This is hopefully unreachable
                    HEAP_ASSERT(false);
                }
            }

            // Cleanup locks if needed
            if (lock[0])
                unlock_page(first, false);

            if (lock[1])
                unlock_page(last, false);
        }

        // Needs to be called before any allocations are made.
        static std::pair< uintptr_t, std::size_t > get_heap_region(HANDLE handle, std::size_t reserve)
        {
            uintptr_t base = 0;
            std::size_t size = 0;
            PROCESS_HEAP_ENTRY entry = { 0 };
            while (HeapWalk(handle, &entry) != FALSE)
            {
                if ((entry.wFlags & PROCESS_HEAP_REGION) != 0)
                {
                    HEAP_ASSERT(entry.Region.dwUnCommittedSize + entry.Region.dwCommittedSize >= reserve);
                    size = entry.Region.dwUnCommittedSize + entry.Region.dwCommittedSize;

                    HEAP_ASSERT(base == 0);
                    base = reinterpret_cast< uintptr_t >(entry.lpData) & get_page_mask();

                    // Walk it till the end to get proper error code
                }
            }

            // If this logic failed, it is serious issue as we are not sure what pages should we protect.

            auto error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
            {
                throw exception("HeapWalk", error);
            }

            HEAP_ASSERT(base != 0);
            HEAP_ASSERT(size >= reserve);
            return { base, size };
        }

    #if defined(HEAP_VERIFY)
        // Check that pages have proper refcounts
        bool verify_refcounts(uintptr_t address, std::size_t pages, bool zero)
        {
            uintptr_t base = get_base_address();

            // Check proper refcount on first page
            uintptr_t index = (address - base) / get_page_size();
            auto refcount = heap_pages_[index].refs.load();
            HEAP_ASSERT(zero ? refcount == 0 : refcount > 0);
            if (pages > 1)
            {
                index = (address + (pages-1)*get_page_size() - base) / get_page_size();
                refcount = heap_pages_[index].refs.load();
                HEAP_ASSERT(zero ? refcount == 0 : refcount > 0);
            }

            return true;
        }

        // Check that pages are locked in the memory
        bool verify_locked(uintptr_t address, std::size_t pages, bool locked)
        {
            std::vector< PSAPI_WORKING_SET_EX_INFORMATION > wset(pages);
            ZeroMemory(&wset[0], wset.size());
            for (std::size_t i = 0; i < pages; ++i)
            {
                wset[i].VirtualAddress = reinterpret_cast< PVOID >(address + i * get_page_size());
            }

            if (QueryWorkingSetEx(GetCurrentProcess(), &wset[0], static_cast<DWORD>(sizeof(wset[0]) * wset.size())) == FALSE)
            {
                throw exception("QueryWorkingSetEx");
            }

            for (std::size_t i = 0; i < pages; ++i)
            {
                HEAP_ASSERT(wset[i].VirtualAttributes.Valid == TRUE);
                HEAP_ASSERT(wset[i].VirtualAttributes.Locked == locked);
            }

            return true;
        }
    #endif

        std::unique_ptr< HANDLE, heap_deleter > heap_;

        struct heap_page
        {
            heap_page()
                : refs(0)
            {}

            std::atomic< uint16_t > refs;

            // TODO: some smaller lock
            std::mutex lock;
        };

        std::unique_ptr < heap_page[] > heap_pages_;

        uintptr_t base_address_;
        std::size_t size_;
        std::atomic< std::size_t > allocated_;
    };
}
