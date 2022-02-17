#include <boost/test/unit_test.hpp>

#include <securememory/allocator.h>

BOOST_AUTO_TEST_CASE(heap_test)
{
	securememory::win32::heap heap(1 << 30);
}

BOOST_AUTO_TEST_CASE(allocator_test)
{
	securememory::win32::heap heap(1 << 10);
	securememory::allocator< char > allocator(&heap);
	
	char *p = allocator.allocate(10);
	allocator.deallocate(p, 10);
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

namespace securememory { win32::heap* global_heap() { static win32::heap heap(1 << 20); return &heap; } }

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
}