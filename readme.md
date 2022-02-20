# std::allocator-compatible allocator that locks pages in memory

Allocator:

- is a wrapper around Win32 Heap
- guarantees that for any successful allocation the underlying pages are locked in memory. For each page, reference
  count of allocations from the page is maintained. As soon as the page is not used anymore, it is unlocked.
- provides lock-free operation for reference counts larger than zero. In other words, unless VirtualLock/VirtualUnlock
  is going to be called, no locks will be taken, except for locks in HeapAllocate/HeapFree.
- minimizes number of VirtualLock/VirtualUnlock calls by working on page ranges whenever possible instead of individual
  pages
- can be compiled with verification enabled to check invariants

Limitations:

- the amount of memory that will be reserved for allocator needs to have a known upper bound. Pages will not be commited
  or locked until requested but the reference counting implementation requires fixed number of consecutive pages
- the heap implementation is provided by Win32 Heap, so it shares limits of Win32 Heaps
