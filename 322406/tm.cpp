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

class blocking_memory
{
public:
    blocking_memory(size_t size) : mx(new std::mutex()), size(size), mem(new char[size]) {}

    ~blocking_memory()
    {
        delete[] mem;
        delete mx;
    }

    void memcpy_read(const char *offset, char *dst, size_t len)
    {
        mx->lock();
        memcpy(dst, offset, len);
        mx->unlock();
    }

    void memcpy_write(char *offset, const char *src, size_t len)
    {
        mx->lock();
        memcpy(offset, src, len);
        mx->unlock();
    }

    char *get_mem() { return mem; }
    size_t get_size() { return size; }

    void acquire() { mx->lock(); }
    void release() { mx->unlock(); }

private:
    std::mutex *mx;
    size_t size;

    // TODO implement free
    char *mem;
};

class stm_log_bloc
{
public:
    stm_log_bloc(blocking_memory *orig, size_t size, size_t align)
        : reads(size / align),
          writes(size / align),
          orig(orig),
          r_value(new char[size]),
          w_value(new char[size]),
          size(size),
          align(align)

    {
    }

    ~stm_log_bloc()
    {
        // delete[] r_value;
        // delete[] w_value;
    }

    bool contains(char *ptr) const
    {
        return ptr >= orig->get_mem() && ptr < (char *)orig->get_mem() + size;
    }

    void read(const char *from, char *to, size_t len)
    {
        // std::cout << "read(" << to << ", " << from << ", " << len << ")\n";
        size_t offset = (char *)from - (char *)orig->get_mem();

        for (size_t i = 0, j = offset / align; i < len; i += align, j++)
        {
            if (writes[j])
            {
                memcpy(r_value + offset + i, w_value + offset + i, align);
                continue;
            }
            if (!reads[j])
            {
                orig->memcpy_read(from + i, r_value + offset + i, align);
                reads[j] = true;
            }
        }

        memcpy(to, r_value + offset, len);
    }

    void write(char *to, const char *from, size_t len)
    {
        size_t offset = (char *)to - (char *)orig->get_mem();
        // std::cout << "write(" << to << ", " << from << ", " << len << ", offset=" << offset << "/" << size << ")\n";

        for (size_t i = 0, j = offset / align; i < len; i += align, j++)
            writes[j] = true;

        memcpy(w_value + offset, from, len);
    }

    bool start_commit()
    {
        orig->acquire();

        // check that reads and writes are consistent

        for (size_t i = 0, j = 0; i < size; i += align, j++)
        {
            if (reads[j])
            {
                if (memcmp(r_value + i, orig->get_mem() + i, align))
                {
                    orig->release();
                    return false;
                }
            }
        }

        return true;
    }

    void rollback()
    {
        orig->release();
    }

    void commit()
    {
        for (size_t i = 0, j = 0; i < size; i += align, j++)
        {
            if (writes[j])
                memcpy(orig->get_mem() + i, w_value + i, align);
        }
        orig->release();
    }

    std::vector<bool> reads, writes;
    blocking_memory *orig;
    char *r_value;
    char *w_value;
    size_t size, align;
};

class transaction
{
public:
    transaction(size_t align) : _align(align) {}
    ~transaction()
    {
        for (auto &&var : _vars)
        {
            delete var.second;
        }
    }
    void read(blocking_memory *mem, const char *from, char *to, size_t len)
    {
        auto it = _vars.find(mem);
        if (it == _vars.end())
        {
            auto bloc = new stm_log_bloc(mem, mem->get_size(), _align);
            it = _vars.emplace(mem, bloc).first;
        }

        it->second->read(from, to, len);
    }

    void write(blocking_memory *mem, const char *from, char *to, size_t len)
    {
        auto it = _vars.find(mem);
        if (it == _vars.end())
        {
            auto bloc = new stm_log_bloc(mem, mem->get_size(), _align);
            it = _vars.emplace(mem, bloc).first;
        }

        it->second->write(to, from, len);
    }

    bool commit()
    {
        std::vector<stm_log_bloc *> acquired;
        bool all_ack = true;
        for (auto &&var : _vars)
        {
            if (!var.second->start_commit())
            {
                all_ack = false;
                break;
            }
            else
                acquired.push_back(var.second);
        }

        if (!all_ack)
        {
            for (auto &&var : acquired)
            {
                var->rollback();
            }
            return false;
        }

        for (auto &&var : acquired)
        {
            var->commit();
        }
        return true;
    }

private:
    std::map<blocking_memory *, stm_log_bloc *> _vars;
    size_t _align;
};

class transactional_mem
{
public:
    transactional_mem(size_t align) : align(align)
    {
    }

    ~transactional_mem()
    {
        for (auto &&bloc : _blocks)
        {
            delete bloc.second;
        }
    }

    blocking_memory *alloc(size_t size)
    {
        auto bloc = new blocking_memory(size);
        _blocks.emplace(bloc->get_mem(), bloc);
        return bloc;
    }

    void read(transaction *tx, const char *from, char *to, size_t len)
    {
        auto it = _blocks.lower_bound(from);
        if (it == _blocks.end())
        {
            std::cout << "oh noz\n";
        }
        tx->read(it->second, from, to, len);
    }

    void write(transaction *tx, const char *from, char *to, size_t len)
    {
        auto it = _blocks.lower_bound(to);
        if (it == _blocks.end())
        {
            std::cout << "oh noz\n";
        }
        tx->write(it->second, from, to, len);
    }

    void alloc_first(size_t size)
    {
        first = alloc(size);
    }

    blocking_memory *get_first() { return first; }
    size_t get_align() { return align; }

private:
    std::map<const char *, blocking_memory *, std::greater<const char *>> _blocks;
    size_t align;
    blocking_memory *first;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t
tm_create(size_t size, size_t align) noexcept
{
    std::cout << "create memory\n";
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
    void *m = mem->get_first()->get_mem();
    std::cout << "start = " << m << "\n";
    return m;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept
{
    MEM;
    return mem->get_first()->get_size();
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
    auto stx = new transaction(mem->get_align());
    return (tx_t)stx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept
{
    (void)shared;
    STX;
    // std::cout << "commit start\n";
    auto success = stx->commit();
    // std::cout << "commit: " << success << "\n";
    delete stx;
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
    mem->read(stx, (const char *)source, (char *)target, size);
    return true;
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
    mem->write(stx, (const char *)source, (char *)target, size);
    return true;
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
    std::cout << "alloc(<< " << size << " <<)\n";
    MEM;
    (void)tx;
    *target = mem->alloc(size)->get_mem();
    return Alloc::success;
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
