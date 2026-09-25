#ifndef KICBA_D9_RECONCILIATION_HASH_H
#define KICBA_D9_RECONCILIATION_HASH_H

/* Shared integer-only sketch primitives for the eBPF and userspace sides. */

#ifndef D9_U64
#define D9_U64 unsigned long long
#endif

#define D9_MASK64 ((D9_U64)~0ULL)
#define D9_FNV_OFFSET ((D9_U64)0xcbf29ce484222325ULL)
#define D9_FNV_PRIME ((D9_U64)0x100000001b3ULL)
#define D9_POS3_SALT ((D9_U64)0xd6e8feb86659fd93ULL)
#define D9_CHECK_SALT ((D9_U64)0xa0761d6478bd642fULL)
#define D9_FP2_SALT ((D9_U64)0xe7037ed1a0b428dbULL)

static __inline D9_U64 d9_mix64(D9_U64 value)
{
    value ^= value >> 30;
    value *= (D9_U64)0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= (D9_U64)0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

static __inline D9_U64 d9_entry_hash_begin(D9_U64 seed1)
{
    return D9_FNV_OFFSET ^ seed1;
}

static __inline D9_U64 d9_entry_hash_byte(D9_U64 value, unsigned char byte)
{
    value ^= (D9_U64)byte;
    value *= D9_FNV_PRIME;
    return value;
}

static __inline D9_U64 d9_entry_hash_finish(
    D9_U64 value, D9_U64 inode, unsigned int d_type,
    unsigned int name_length, D9_U64 seed1, D9_U64 seed2)
{
    value ^= d9_mix64(inode ^ seed2);
    value ^= d9_mix64(
        ((D9_U64)(d_type & 0xffU)) ^
        ((D9_U64)(name_length & 0xffffU) << 8) ^ seed1);
    return d9_mix64(value);
}

static __inline D9_U64 d9_token_check(
    D9_U64 key_hash, D9_U64 inode, unsigned int d_type,
    D9_U64 seed1, D9_U64 seed2)
{
    D9_U64 value = key_hash ^ d9_mix64(inode ^ seed1);
    value ^= ((D9_U64)(d_type & 0xffU) << 56) ^ seed2 ^ D9_CHECK_SALT;
    return d9_mix64(value);
}

static __inline D9_U64 d9_fingerprint_second(
    D9_U64 key_hash, D9_U64 inode, unsigned int d_type)
{
    return d9_mix64(key_hash ^ inode ^ D9_FP2_SALT) ^
           d9_mix64((D9_U64)(d_type & 0xffU));
}

static __inline unsigned int d9_position_1(
    D9_U64 key_hash, D9_U64 seed1, unsigned int mask)
{
    return (unsigned int)(d9_mix64(key_hash ^ seed1) & mask);
}

static __inline unsigned int d9_position_2(
    D9_U64 key_hash, D9_U64 seed2, unsigned int mask,
    unsigned int first)
{
    unsigned int second =
        (unsigned int)(d9_mix64(key_hash ^ seed2) & mask);
    if (second == first)
        second = (second + 1U) & mask;
    return second;
}

static __inline unsigned int d9_position_3(
    D9_U64 key_hash, D9_U64 seed1, D9_U64 seed2,
    unsigned int mask, unsigned int first, unsigned int second)
{
    unsigned int third = (unsigned int)(
        d9_mix64(key_hash ^ seed1 ^ seed2 ^ D9_POS3_SALT) & mask);
    if (third == first || third == second)
        third = (third + 1U) & mask;
    if (third == first || third == second)
        third = (third + 1U) & mask;
    return third;
}

#endif
