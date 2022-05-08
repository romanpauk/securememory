//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <array>
#include <atomic>

namespace securememory::win32
{
    template < typename T > class page_table
    {
        template < typename T > class directory
        {
        public:
            ~directory()
            {
                for (auto& value : data_)
                {
                    delete value;
                }
            }

            T& operator[](uintptr_t offset)
            {
                while(true)
                {
                    T* p = data_[offset].load(std::memory_order_relaxed);
                    if (!p)
                    {
                        // TODO: small objects could be placed into the map directly
                        auto node = std::make_unique< T >();
                        T* expected = 0;
                        if (data_[offset].compare_exchange_weak(expected, node.get(), std::memory_order_release))
                        {
                            return *node.release();
                        }
                        else if(expected)
                        {
                            return *expected;
                        }
                    }
                    return *p;
                }
            }

        private:
            std::array< std::atomic< T* >, 1 << 9 > data_;
        };

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
        directory< directory< directory< directory< T > > > > directory_;
    };
}
