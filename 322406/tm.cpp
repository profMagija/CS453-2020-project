/**
 * @file   tm.cpp
 * @author Nikola Bebić
 *
 * @section LICENSE
 *
 *            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 *
 *  0. You just DO WHAT THE FUCK YOU WANT TO.
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#ifdef __STDC_NO_ATOMICS__
#error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <atomic>
#include <memory>
#include <vector>
#include <mutex>
#include <set>
#include <bitset>
#include <cstring>
#include <map>
#include <algorithm>
#include <iostream>
#include <thread>

// Internal headers
#include <tm.hpp>

// -------------------------------------------------------------------------- //

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
#define likely(prop) \
    __builtin_expect((prop) ? 1 : 0, 1)
#else
#define likely(prop) \
    (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
#define unlikely(prop) \
    __builtin_expect((prop) ? 1 : 0, 0)
#else
#define unlikely(prop) \
    (prop)
#endif

// -------------------------------------------------------------------------- //

std::atomic_size_t global_lock;

template <typename value_t>
class stx
{
public:
    stx()
    {
        reads.reserve(100);
    }

public:
    void begin()
    {
        do
        {
            snapshot = global_lock.load();
        } while (snapshot & 1);
    }

    std::pair<bool, value_t> read(value_t *address)
    {
        auto it = writes.find(address);
        if (it != writes.end())
        {
            // std::cout << "[" << std::this_thread::get_id() << " " << (void *)this << "] "
            //           << "bueno\n";
            return std::make_pair(true, it->second);
        }

        auto val = *address;
        while (snapshot != global_lock.load())
        {
            auto rv = validate();
            if (!rv.first)
                return std::make_pair(false, 0);
            snapshot = rv.second;
            val = *address;
        }

        reads.push_back(std::make_pair(address, val));
        // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] " << "read(" << address << ") -> " << val << "\n";
        return std::make_pair(true, val);
    }

    void write(value_t *address, value_t value)
    {
        // std::cout << "[" << std::this_thread::get_id() << " " << (void *)this << "] "
        //           << "write(" << address << ", " << value << ")\n";
        writes.insert_or_assign(address, value);
    }

    bool commit()
    {
        if (writes.empty())
            return true;

        size_t exp = snapshot;
        while (!global_lock.compare_exchange_strong(exp, snapshot + 1))
        {
            auto rv = validate();
            if (!rv.first)
            {
                return false;
            }
            snapshot = rv.second;
            exp = snapshot;
        }

        for (auto const &[addr, val] : writes)
        {
            // std::cout << "[" << std::this_thread::get_id() << " " << (void *)this << "] "
            //           << "commit_write(" << addr << ", " << val << ")\n";
            *addr = val;
        }

        global_lock.store(snapshot + 2);
        return true;
    }

private:
    std::pair<bool, size_t> validate()
    {
        while (true)
        {
            size_t time = global_lock.load();
            if (time & 1)
                continue;

            for (auto const &read : reads)
                if (*(read.first) != read.second)
                    return std::make_pair(false, 0);

            if (time == global_lock.load())
                return std::make_pair(true, time);
        }
    }

private:
    size_t snapshot;
    std::vector<std::pair<value_t *, value_t>> reads;
    std::map<value_t *, value_t> writes;
};

typedef stx<uint64_t> transaction;

template <typename value_t>
class stm
{
public:
    stm(size_t align) : align(align)
    {
    }

    uint8_t *alloc(size_t size)
    {
        auto bloc = new uint8_t[size + 8];
        memset(bloc, 0, size + 8);
        *(size_t *)bloc = size;
        // _blocks.emplace(bloc, bloc);
        return bloc;
    }

    bool read(transaction *tx, const value_t *from, value_t *to, size_t len)
    {
        auto ptr = from;
        auto tptr = to;
        for (; ptr < from + len; ptr += align, tptr += align)
        {
            auto rv = tx->read((value_t *)ptr);
            if (!rv.first)
                return false;

            // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] "
            //           << "we got " << rv.second << "\n";
            *(volatile value_t *)tptr = rv.second;
            // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] "
            //           << "we made " << *(value_t *)tptr << "\n";
        }
        return true;
    }

    bool write(transaction *tx, const value_t *from, value_t *to, size_t len)
    {
        auto ptr = from;
        auto tptr = to;
        // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] " << "tx->write(" << (void *)from << ", " << (void *)to << ", " << len << ")\n";

        for (; ptr < from + len; ptr += align, tptr += align)
        {
            tx->write(tptr, *ptr);
        }
        return true;
    }

    void alloc_first(size_t size)
    {
        first = alloc(size);
        first_size = size;
    }

    void *get_first() { return first; }
    size_t get_first_size() { return first_size; }
    size_t get_align() { return align; }

private:
    // std::map<const char *, void *, std::greater<const char *>> _blocks;
    size_t align;
    size_t first_size;
    void *first;
};

typedef stm<uint64_t> transactional_mem;

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t
tm_create(size_t size, size_t align) noexcept
{
    // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] " << "create memory\n";
    auto mem = new transactional_mem(align);
    mem->alloc_first(size);
    return (shared_t)mem;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/

#define MEM transactional_mem *mem = (transactional_mem *)shared
#define STX transaction *stx = (transaction *)tx

void tm_destroy(shared_t shared) noexcept
{
    MEM;
    delete mem;
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void *tm_start(shared_t shared) noexcept
{
    MEM;
    void *m = mem->get_first();
    // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] " << "start = " << m << "\n";
    return m;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept
{
    MEM;
    return mem->get_first_size();
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept
{
    MEM;
    return mem->get_align();
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept
{
    (void)is_ro;
    MEM;
    auto stx = new transaction();
    stx->begin();
    return (tx_t)stx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept
{
    // static int num_succ = 0;
    // static int num_failed = 0;
    (void)shared;
    STX;
    // std::cout << "[" << std::this_thread::get_id() << " " << (void *)tx << "] "
    //           << "commit start\n";
    auto success = stx->commit();
    // std::cout << "[" << std::this_thread::get_id() << " " << (void *)tx << "] "
    //           << "commit: " << (success ? "ok" : "abort") << "\n";
    delete stx;
    // if (!success)
    // {
    //     std::cout << num_succ << " / " << num_failed++ << " execution\r";
    // }
    // else
    // {
    //     std::cout << num_succ++ << " / " << num_failed << " execution\r";
    // }
    return success;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const *source, size_t size, void *target) noexcept
{
    MEM;
    STX;
    // const char *src = (const char *)source;
    // if (src < (const void *)0x1000)
    // {
    //     src += (size_t)mem->get_first()->get_mem();
    // }
    auto rv = mem->read(stx, (const uint64_t *)source, (uint64_t *)target, size);
    // std::cout << "[" << std::this_thread::get_id() << " " << (void *)tx << "] "
    //           << "read(" << source << ") -> " << *(uint64_t *)target
    //           << " [" << (rv ? "ok" : "abort") << "]\n";
    return rv;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const *source, size_t size, void *target) noexcept
{
    MEM;
    STX;
    auto rv = mem->write(stx, (const uint64_t *)source, (uint64_t *)target, size);
    // std::cout << "[" << std::this_thread::get_id() << " " << (void *)tx << "] "
    //           << "write(" << target << ", " << *(const volatile uint64_t *)source << ")"
    //           << " [" << (rv ? "ok" : "abort") << "]\n";
    return rv;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t tx, size_t size, void **target) noexcept
{
    MEM;
    (void)tx;
    *target = mem->alloc(size);
    // std::cout << "[" << std::this_thread::get_id() << " " << (void*)this << "] " << "alloc(" << size << ") -> [" << *target << ", " << (void *)(((uintptr_t)*target) + size) << "]\n";
    return *target != nullptr ? Alloc::success : Alloc::nomem;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t tx, void *target) noexcept
{
    (void)shared;
    (void)tx;
    (void)target;
    // TODO
    return true;
}
