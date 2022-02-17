// https://howardhinnant.github.io/allocator_boilerplate.html

#if defined(_WIN32)
#include <securememory/win32/heap.h>
#endif

namespace securememory
{
    template <class T, class Heap = win32::heap >
    class allocator
    {
        template <class U, class Heap > friend class allocator;

    public:
        using value_type    = T;

        allocator() noexcept
            : heap_(global_heap())
        {}
        
        allocator(Heap* heap) noexcept
            : heap_(heap)
        {}

        template <class U> allocator(allocator<U, Heap> const& other) noexcept 
            : heap_(other.heap_)
        {}

        value_type* allocate(std::size_t n)
        {
            if (std::numeric_limits<std::size_t>::max() / sizeof(value_type) < n)
            {
                throw std::bad_array_new_length();
            }

            auto ptr = reinterpret_cast< value_type* >(heap_->allocate(n * sizeof(value_type)));
            if (!ptr)
            {
                throw std::bad_alloc();
            }

            return ptr;
        }

        void deallocate(value_type* p, std::size_t size) noexcept 
        {
            heap_->deallocate(p, size);
        }

    private:
        Heap* heap_;
    };

    template <class T, class U, class Heap> bool operator == (allocator<T, Heap> const& lhs, allocator<U, Heap> const& rhs) noexcept
    {
        return lhs.heap_ == rhs.heap_;
    }

    template <class T, class U, class Heap> bool operator != (allocator<T, Heap> const& x, allocator<U, Heap> const& y) noexcept
    {
        return !(x == y);
    }
}