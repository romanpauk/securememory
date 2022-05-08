//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <array>
#include <atomic>
#include <type_traits>

namespace securememory::win32
{
    template < typename T >
    class page_allocator
    {
        template <class U > friend class page_allocator;

    public:
        using value_type = T;

        page_allocator() noexcept
        {}

        template <class U> page_allocator(page_allocator<U> const& other) noexcept
        {}

        value_type* allocate(std::size_t n)
        {
            if (std::numeric_limits<std::size_t>::max() / sizeof(value_type) < n)
            {
                throw std::bad_array_new_length();
            }

            auto ptr = reinterpret_cast<value_type*>(VirtualAlloc(NULL, n * sizeof(value_type), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!ptr)
            {
                throw std::bad_alloc();
            }

            return ptr;
        }

        void deallocate(value_type* p, std::size_t n) noexcept
        {
            VirtualFree(p, n * sizeof(value_type), MEM_RELEASE);
        }
    };

    template <class T, class U, class Heap> bool operator == (page_allocator<T> const& lhs, page_allocator<U> const& rhs) noexcept
    {
        return true;
    }

    template <class T, class U, class Heap> bool operator != (page_allocator<T> const& x, page_allocator<U> const& y) noexcept
    {
        return !(x == y);
    }

    template < typename T, typename Allocator = void, bool IsPointer = std::is_pointer_v< T > > class page_directory;

    template < typename T, typename Allocator > class page_directory< T, Allocator, true >
    {
    public:
        using value_type = std::remove_pointer_t< T >;

        ~page_directory()
        {
            std::allocator_traits< Allocator >::template rebind_alloc< value_type > alloc;
            for (auto& value : data_)
            {
                alloc.deallocate(value, 1);
            }
        }

        value_type& operator[](uintptr_t offset)
        {
            while (true)
            {
                value_type* p = data_[offset].load(std::memory_order_relaxed);
                if (!p)
                {
                    std::allocator_traits< Allocator >::template rebind_alloc< value_type > alloc;
                    auto n = alloc.allocate(1);

                    value_type* expected = 0;
                    if (data_[offset].compare_exchange_weak(expected, n, std::memory_order_release))
                    {
                        return *n;
                    }
                    else if (expected)
                    {
                        alloc.deallocate(n, 1);
                        return *expected;
                    }
                    else
                    {
                        alloc.deallocate(n, 1);
                    }
                }
                return *p;
            }
        }

    private:
        std::array< std::atomic< value_type* >, 1 << 9 > data_;
    };

    template < typename T > class page_directory< T, void, false >
    {
    public:
        static_assert(sizeof(T) <= sizeof(void*));

        using value_type = T;

        value_type& operator[](uintptr_t offset)
        {
            return data_[offset];
        }

    private:
        std::array< value_type, 1 << 9 > data_;
    };

    template < typename T, typename Allocator = page_allocator< T > > class page_table
    {
    public:
        page_table() {}

        T& operator[](uintptr_t address)
        {
            // 16 - 9 - 9 - 9 - 9 - 12
            uintptr_t offset3 = (address >> 12) & ((1 << 9) - 1);
            uintptr_t offset2 = (address >> (12 + 9)) & ((1 << 9) - 1);
            uintptr_t offset1 = (address >> (12 + 9 + 9)) & ((1 << 9) - 1);
            uintptr_t offset0 = (address >> (12 + 9 + 9 + 9)) & ((1 << 9) - 1);

            return directory_[offset0][offset1][offset2][offset3];
        }

        void erase(uintptr_t address);

    private:
        page_directory< page_directory< page_directory< page_directory< T >*, Allocator >*, Allocator >*, Allocator > directory_;
    };
}
