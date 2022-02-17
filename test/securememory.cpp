#include <boost/test/unit_test.hpp>

#include <securememory/allocator.h>

BOOST_AUTO_TEST_CASE(heap_test)
{
    securememory::win32::heap heap(1 << 30);
    heap.allocate(1);
}

BOOST_AUTO_TEST_CASE(allocator_locked_test)
{
    securememory::win32::heap heap(1 << 20);
    securememory::allocator< char > allocator(&heap);
    
    BOOST_CHECK(heap.locked_size() == 0);

    const size_t count = 64;
    const size_t size = 1000;
    std::vector< char* > ptrs;
    for (size_t i = 0; i < count; ++i)
    {
        char* p = allocator.allocate(size);
        std::cerr << "allocate: " << i << ": locked " << heap.locked_size() << std::endl;
        ptrs.push_back(p);
    }

    BOOST_CHECK(heap.locked_size() > 0);

    for (size_t i = 0; i < count; ++i)
    {
        allocator.deallocate(ptrs[i], size);
        std::cerr << "deallocate: " << i << ": locked " << heap.locked_size() << std::endl;
    }

    BOOST_CHECK(heap.locked_size() == 0);
}

BOOST_AUTO_TEST_CASE(vector_test)
{
    const size_t size = 1 << 10;
    securememory::win32::heap heap(size);
    securememory::allocator< char > allocator(&heap);

    std::vector< char, decltype(allocator) > vec(allocator);
    vec.reserve(size / 2);

    BOOST_CHECK_THROW(vec.reserve(size * 200), std::bad_alloc);
}

namespace securememory 
{ 
    win32::heap* global_heap() 
    {
        static win32::heap heap(1 << 20); 
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