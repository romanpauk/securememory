//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <cassert>
#include <stdexcept>
#include <mutex>

// HEAP_LOCK_MULTIPLE works on block of pages, minimizing number of VirtualLock/Unlock calls.
// But the code is slightly more complex than simple version working page-by-page.
#define HEAP_LOCK_MULTIPLE
#define HEAP_VERIFY

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

        std::size_t get_locked_size() const
        {
            std::size_t count = 0;
            for (std::size_t i = 0; i < (size_ + get_page_size()) / get_page_size(); ++i)
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

    private:
    #if defined(HEAP_LOCK_MULTIPLE)
        //
        // Returns block of pages that all either:
        //     a) have refcount = 0 and are locked (to be locked in ram)
        //     b) have refcount > 0 and are not locked (as they are locked in ram already)
        // The code tries to accumulate as large block as possible where all pages have
        // the same property - a) or b).
        //
        std::pair< std::size_t, bool > acquire_pages(uintptr_t address, std::size_t pages)
        {
            uintptr_t base = get_base_address();

            std::pair< std::size_t, const bool > range[] = { { 0, true }, { 0, false } };

            for (size_t i = 0; i < pages; ++i)
            {
                uintptr_t index = (address + i * get_page_size() - base) / get_page_size();

                do
                {
                    auto count = heap_pages_[index].refs.load();
                    if (count == 0)
                    {
                        if (range[1].first)
                        {
                            goto out;
                        }

                        // Page is not locked in memory. Get lock on the page.
                        // The lock is needed as in deallocate, we might mistakenly unlock the page from memory.

                        heap_pages_[index].lock.lock();
                        if (heap_pages_[index].refs.load() == 0)
                        {
                            // The page is still not in the memory, keep it locked and add it to the range
                            range[0].first += 1;
                            break;
                        }
                        else
                        {
                            // Page refcount was incremented in the meantime. Try again.
                            heap_pages_[index].lock.unlock();
                        }
                    }
                    else
                    {
                        if (range[0].first)
                        {
                            goto out;
                        }

                        if (heap_pages_[index].refs.compare_exchange_strong(count, count + 1))
                        {
                            // As refcount was properly increased from count to count + 1 the page is in the memory.
                            // We do not fetch_add here as that would allow fetch_add to go from 0 to 1, while not locking
                            // the page in memory.

                            range[1].first += 1;
                            break;
                        }
                    }
                } while (true);
            }

            // Return the accumulated range
        out:
            if (range[0].first)
            {
                HEAP_ASSERT(range[1].first == 0);
                HEAP_ASSERT(verify_refcounts(address, range[0].first, range[0].second));
                return range[0];
            }
            else
            {
                HEAP_ASSERT(range[0].first == 0);
                HEAP_ASSERT(verify_refcounts(address, range[0].first, range[0].second));
                return range[1];
            }
        }

        //
        // The same as acquire_pages() but for deallocation, returns block of pages that all either:
        //      a) have refcount = 0 after decrementing and are locked (to be unlocked from memory)
        //      b) have refcount > 0 after decrementing and are not locked (as they will stay locked in memory)
        //
        std::pair< std::size_t, bool > release_pages(uintptr_t address, std::size_t pages)
        {
            uintptr_t base = get_base_address();

            std::pair< std::size_t, const bool > range[] = { { 0, true }, { 0, false } };

            for (size_t i = 0; i < pages; ++i)
            {
                uintptr_t index = (address + i * get_page_size() - base) / get_page_size();

                do
                {
                    auto count = heap_pages_[index].refs.load();
                    if (count == 1)
                    {
                        if (range[1].first)
                        {
                            // If there is a previous range, return it.
                            goto out;
                        }

                        if (heap_pages_[index].refs.compare_exchange_strong(count, 0))
                        {
                            heap_pages_[index].lock.lock();
                            if (heap_pages_[index].refs.load() == 0)
                            {
                                // The page refcount was not incremented in the meantime, add to range to unlock from memory.
                                range[0].first += 1;
                                break;
                            }
                            else
                            {
                                // The page refcount was incremented in the meantime. Try again.
                                heap_pages_[index].lock.unlock();
                            }
                        }
                        else
                        {
                            // The page refcount was incremented in the meantime. Try again.
                        }
                    }
                    else
                    {
                        HEAP_ASSERT(count > 1);

                        if (range[0].first)
                        {
                            // If there is a previous range, return it.
                            goto out;
                        }

                        if (heap_pages_[index].refs.compare_exchange_strong(count, count - 1))
                        {
                            range[1].first += 1;
                            break;
                        }
                    }
                } while (true);
            }

            // Return the accumulated range
        out:
            if (range[0].first)
            {
                HEAP_ASSERT(range[1].first == 0);
                HEAP_ASSERT(verify_refcounts(address, range[0].first, range[0].second));
                return range[0];
            }
            else
            {
                HEAP_ASSERT(range[0].first == 0);
                HEAP_ASSERT(verify_refcounts(address, range[0].first, range[0].second));
                return range[1];
            }
        }

        void unlock_pages(uintptr_t address, std::size_t pages, uint16_t refcount)
        {
            uintptr_t base = get_base_address();

            for (size_t i = 0; i < pages; ++i)
            {
                uintptr_t index = (address + i * get_page_size() - base) / get_page_size();

                if (refcount)
                {
                    heap_pages_[index].refs.fetch_add(refcount);
                }

                heap_pages_[index].lock.unlock();
            }
        }
    #endif

        bool lock_address_range(void* ptr, std::size_t size)
        {
            uintptr_t address = reinterpret_cast<uintptr_t>(ptr) & get_page_mask();
            uintptr_t base = get_base_address();
            std::size_t pages = (size + get_page_size()) / get_page_size();

        #if defined(HEAP_LOCK_MULTIPLE)
            while(pages)
            {
                auto [n, locked] = acquire_pages(address, pages);
                if (locked)
                {
                    if (!VirtualLock(reinterpret_cast<LPVOID>(address), n * get_page_size()))
                    {
                        unlock_pages(address, n, 0);
                        return false;
                    }

                    unlock_pages(address, n, 1);
                }

                address += n * get_page_size();
                pages -= n;
            }
        #else
            for (size_t i = 0; i < pages; ++i, address += get_page_size())
            {
                uintptr_t index = (address - base) / get_page_size();

                do
                {
                    auto count = heap_pages_[index].refs.load();
                    if (count == 0)
                    {
                        // Page is not locked in memory. Get lock on the page and lock it in memory.
                        // The lock is needed as in deallocate, we might mistakenly unlock the page from memory.

                        std::unique_lock< std::mutex > lock(heap_pages_[index].lock);

                        if (heap_pages_[index].refs.load() == 0)
                        {
                            if (!VirtualLock(reinterpret_cast<LPVOID>(address), get_page_size()))
                            {
                                // We failed to lock the pages in memory so we don't have a secure allocation.
                                // Unlock all but last page we tried to lock.

                                HEAP_ASSERT(false);

                                if (i > 0)
                                {
                                    lock.unlock();
                                    unlock_address_range(ptr, i * get_page_size());
                                }

                                return false;
                            }
                        }

                        heap_pages_[index].refs.fetch_add(1);
                        break;
                    }
                    else if (heap_pages_[index].refs.compare_exchange_strong(count, count + 1))
                    {
                        // Page seemed to be locked and as refcount was properly increased from count to count + 1 it really is.
                        // We do not fetch_add here as that could cause fetch_add to set refcount to 1, even though the page was
                        // just unlocked from memory.
                        break;
                    }
                    else
                    {
                        // Someone else either decreased or increased the refcount, try again.
                        continue;
                    }
                } while (true);
            }
        #endif

            HEAP_ASSERT(verify_refcounts(reinterpret_cast<uintptr_t>(ptr) & get_page_mask(), (size + get_page_size()) / get_page_size(), false));
            HEAP_ASSERT(verify_locked(reinterpret_cast<uintptr_t>(ptr)& get_page_mask(), (size + get_page_size()) / get_page_size(), true));
            return true;
        }

        void unlock_address_range(void* ptr, std::size_t size)
        {
            uintptr_t address = reinterpret_cast<uintptr_t>(ptr) & get_page_mask();
            uintptr_t base = get_base_address();
            std::size_t pages = (size + get_page_size()) / get_page_size();

            HEAP_ASSERT(verify_refcounts(reinterpret_cast<uintptr_t>(ptr) & get_page_mask(), (size + get_page_size()) / get_page_size(), false));
            HEAP_ASSERT(verify_locked(reinterpret_cast<uintptr_t>(ptr) & get_page_mask(), (size + get_page_size()) / get_page_size(), true));

        #if defined(HEAP_LOCK_MULTIPLE)
            while (pages)
            {
                auto [n, locked] = release_pages(address, pages);
                if (locked)
                {
                    if (!VirtualUnlock(reinterpret_cast<LPVOID>(address), n * get_page_size()))
                    {
                        HEAP_ASSERT(false);
                    }

                    unlock_pages(address, n, 0);
                }

                address += n * get_page_size();
                pages -= n;
            }
        #else
            for (size_t i = 0; i < pages; ++i, address += get_page_size())
            {
                uintptr_t index = (address - base) / get_page_size();

                auto count = heap_pages_[index].refs.fetch_sub(1);
                if (count == 1)
                {
                    // Refcount is 0 now, the page should be unlocked from memory.
                    std::lock_guard< std::mutex > lock(heap_pages_[index].lock);

                    if (heap_pages_[index].refs.load() == 0)
                    {
                        // Refcount is really 0 and as any potential increment is under lock, we can safely unlock it from memory.
                        if (!VirtualUnlock(reinterpret_cast<LPVOID>(address), get_page_size()))
                        {
                            // The fact that we failed to unlock a page from memory may be serious.
                            HEAP_ASSERT(false);
                        }
                    }
                    else
                    {
                        // Someone incremented the refcount, don't unlock the page from memory
                    }
                }
                else
                {
                    HEAP_ASSERT(count > 1);
                }
            }
        #endif
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
        bool verify_refcounts(uintptr_t address, std::size_t pages, bool zero)
        {
            uintptr_t base = get_base_address();

            for (size_t i = 0; i < pages; ++i)
            {
                uintptr_t index = (address + i * get_page_size() - base) / get_page_size();
                auto refcount = heap_pages_[index].refs.load();
                HEAP_ASSERT(zero ? refcount == 0 : refcount > 0);
            }

            return true;
        }

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
