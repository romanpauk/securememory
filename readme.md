# std::allocator-compatible allocator that locks pages in memory

Allocator:

- is a wrapper around Win32 Heap
- guarantees that for any successful allocation the underlying pages are locked in memory
- works with page ranges instead of individual pages. For each allocation, only first and last page of the allocation
  needs to be worked with.
- provides lock-free operation for reference counts larger than zero. In other words, unless VirtualLock/VirtualUnlock
  is going to be called because of range reference count will increase from zero or decrease to zero, no locks will be
  taken, except for locks already present in HeapAllocate/HeapFree.
- can be compiled with verification enabled to check invariants

Limitations:

- the amount of memory that will be reserved for allocator needs to have a known upper bound. Pages will not be commited
  or locked until requested but the reference counting implementation requires fixed number of consecutive pages
- the heap implementation is provided by Win32 Heap, so it shares limits of Win32 Heaps. As the heap is non-growable,
  maximum allocation size it can provide must be less than 0x7FFF8.

Notes:

- working with page ranges makes hash table a good candidate for the datastructure maintaining reference counts
- if this hash table will be resizable, the heap can be growable, getting rid of some of the above limitations (notably
  allocation size)
