//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <boost/test/unit_test.hpp>
#include <boost/mpl/list.hpp>

#include <securememory/allocator.h>

#include <set>
#include <thread>

using assertion_types = boost::mpl::list <
#if !defined(_DEBUG)
    securememory::win32::assertions< false >,
#endif
    securememory::win32::assertions< true >
>;

BOOST_AUTO_TEST_CASE(heap_virtual_lock_unlock)
{
    uint8_t* ptr = (uint8_t*)VirtualAlloc(0, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOST_CHECK(ptr);

    // Check that we can lock/unlock different sizes.

    // Lock two pages
    BOOST_CHECK(VirtualLock(ptr, 8192));
    BOOST_CHECK(VirtualLock(ptr, 8192));

    // Unlock second one
    BOOST_CHECK(VirtualUnlock(ptr + 4096, 1));
    BOOST_CHECK(VirtualUnlock(ptr + 4096, 1) == FALSE);

    // Unlock first one
    BOOST_CHECK(VirtualUnlock(ptr, 20));
    BOOST_CHECK(VirtualUnlock(ptr, 20) == FALSE);

    BOOST_CHECK(VirtualFree(ptr, 0, MEM_RELEASE));
}

BOOST_AUTO_TEST_CASE(heap_test_pagesize)
{
    BOOST_CHECK(securememory::win32::heap::get_page_size() == 4096);
    BOOST_CHECK(securememory::win32::heap::get_pages(1) == 1);
    BOOST_CHECK(securememory::win32::heap::get_pages(4096) == 1);
    BOOST_CHECK(securememory::win32::heap::get_pages(4097) == 2);
    BOOST_CHECK(securememory::win32::heap::get_pages(8192) == 2);
    BOOST_CHECK(securememory::win32::heap::get_pages(8193) == 3);

    BOOST_CHECK(~securememory::win32::heap::get_page_size_mask() + 1 == securememory::win32::heap::get_page_size());
    BOOST_CHECK((1234 << securememory::win32::heap::get_page_size_log()) == (1234 * securememory::win32::heap::get_page_size()));
}

BOOST_AUTO_TEST_CASE(heap_reserve_test)
{
    BOOST_CHECK_THROW(securememory::win32::heap(0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(allocator_locked_test, Assertion, assertion_types)
{
    securememory::win32::basic_heap< Assertion > heap(1 << 20);
    securememory::allocator< char, decltype(heap) > allocator(&heap);

    BOOST_CHECK(heap.get_locked_size() == 0);

    const size_t count = 64;
    const size_t size = 1000;
    std::vector< char* > ptrs;
    for (size_t i = 0; i < count; ++i)
    {
        char* p = allocator.allocate(size);
        std::cerr << "allocate: " << i << ": locked " << heap.get_locked_size() << std::endl;
        ptrs.push_back(p);
    }

    BOOST_CHECK(heap.get_locked_size() > 0);

    for (size_t i = 0; i < count; ++i)
    {
        allocator.deallocate(ptrs[i], size);
        std::cerr << "deallocate: " << i << ": locked " << heap.get_locked_size() << std::endl;
    }

    BOOST_CHECK(heap.get_locked_size() == 0);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(vector_test, Assertion, assertion_types)
{
    const size_t size = 1 << 10;
    securememory::win32::basic_heap< Assertion > heap(size);
    securememory::allocator< char, decltype(heap) > allocator(&heap);

    std::vector< char, decltype(allocator) > vec(allocator);
    vec.reserve(size / 2);

    BOOST_CHECK_THROW(vec.reserve(size * 200), std::bad_alloc);
}

namespace securememory
{
    win32::heap* global_heap()
    {
        static win32::heap heap(1 << 30);
        return &heap;
    }
}

BOOST_AUTO_TEST_CASE(vector_test_global)
{
    // This just tests that the code compiles with the global_heap() function.
    std::vector< char, securememory::allocator< char > > vec;
    vec.resize(10);
}

BOOST_AUTO_TEST_CASE(map_test_global)
{
    // This just tests that the code compiles with the global_heap() function.
    std::map< int, std::string, std::less< int >, securememory::allocator< std::pair< const int, std::string > > > map;
    map.emplace(1, "aaa");

    std::vector< std::string, securememory::allocator < std::string > > vec;
    vec.emplace_back("bbb");
}

BOOST_AUTO_TEST_CASE_TEMPLATE(parallel_test, Assertion, assertion_types)
{
    const int count = 100000;
    const auto workers = std::thread::hardware_concurrency();

    securememory::win32::basic_heap< Assertion > heap(1 << 30);

    std::vector< std::thread > threads;
    for (size_t i = 0; i < workers; ++i)
    {
        threads.emplace_back([count, &heap]()
        {
            securememory::allocator< int, securememory::win32::basic_heap< Assertion > > allocator(&heap);
            std::set< int, std::less< int >, decltype(allocator) > set(allocator);

            for (int i = 0; i < count; ++i)
            {
                set.insert(i);

                if (i % 2 == 0)
                {
                    set.erase(i / 2);
                }
            }
        });
    }

    for (size_t i = 0; i < threads.size(); ++i)
    {
        threads[i].join();
    }
}
