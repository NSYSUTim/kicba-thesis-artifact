/* Name hashing macros copied unchanged from the frozen phase-one diagnostic. */
#define D9_NAME_MAX 255
#define D9_S_DT_MASK 15U

#define D9_HASH_ONE(N)                                                   \
    do {                                                                 \
        if (name_length > (N))                                           \
            value = d9_entry_hash_byte(                                  \
                value, (unsigned char)raw[(N)]);                          \
    } while (0)
#define D9_HASH_BYTE_AT(N)                                               \
    value = d9_entry_hash_byte(value, (unsigned char)raw[(N)])
#define D9_HASH_EIGHT(B)                                                 \
    do {                                                                 \
        if (name_length >= (B) + 8) {                                   \
            D9_HASH_BYTE_AT((B) + 0); D9_HASH_BYTE_AT((B) + 1);          \
            D9_HASH_BYTE_AT((B) + 2); D9_HASH_BYTE_AT((B) + 3);          \
            D9_HASH_BYTE_AT((B) + 4); D9_HASH_BYTE_AT((B) + 5);          \
            D9_HASH_BYTE_AT((B) + 6); D9_HASH_BYTE_AT((B) + 7);          \
        } else if (name_length > (B)) {                                 \
            D9_HASH_ONE((B) + 0); D9_HASH_ONE((B) + 1);                 \
            D9_HASH_ONE((B) + 2); D9_HASH_ONE((B) + 3);                 \
            D9_HASH_ONE((B) + 4); D9_HASH_ONE((B) + 5);                 \
            D9_HASH_ONE((B) + 6); D9_HASH_ONE((B) + 7);                 \
        }                                                                \
    } while (0)

