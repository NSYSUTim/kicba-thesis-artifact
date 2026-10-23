/* Build the userspace-side fingerprint and IBLT over a complete getdents64 scan. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define D9_U64 uint64_t
#include "../collector/d9_reconciliation_hash.h"

struct d9_linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

struct d9_cell {
    int32_t count;
    uint64_t key_xor;
    uint64_t inode_xor;
    uint64_t type_xor;
    uint64_t check_xor;
};

struct exact_record {
    struct exact_record *next;
    uint64_t inode;
    unsigned int d_type;
    size_t length;
    unsigned char name[];
};

static int write_exact(FILE *stream, struct exact_record *record)
{
    while (record) {
        struct exact_record *next = record->next;
        size_t index;
        fprintf(stream, "{\"inode\":%" PRIu64 ",\"d_type\":%u,\"name_hex\":\"",
                record->inode, record->d_type);
        for (index = 0; index < record->length; index++)
            fprintf(stream, "%02x", (unsigned int)record->name[index]);
        fputs("\"}\n", stream);
        free(record);
        record = next;
    }
    return ferror(stream) ? -1 : 0;
}

static uint64_t parse_u64(const char *text, const char *label)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || !end || end == text || *end || text[0] < '0' || text[0] > '9') {
        fprintf(stderr, "invalid %s: %s\n", label, text);
        exit(2);
    }
    return (uint64_t)value;
}

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end)
{
    uint64_t seconds = (uint64_t)(end->tv_sec - start->tv_sec);
    int64_t nanos = end->tv_nsec - start->tv_nsec;
    if (nanos < 0) {
        seconds--;
        nanos += 1000000000LL;
    }
    return seconds * 1000000000ULL + (uint64_t)nanos;
}

static void update_cell(
    struct d9_cell *cells, unsigned int index,
    uint64_t key_hash, uint64_t inode, unsigned int d_type,
    uint64_t seed1, uint64_t seed2)
{
    struct d9_cell *cell = &cells[index];
    cell->count++;
    cell->key_xor ^= key_hash;
    cell->inode_xor ^= inode;
    cell->type_xor ^= d_type;
    cell->check_xor ^= d9_token_check(
        key_hash, inode, d_type, seed1, seed2);
}

int main(int argc, char **argv)
{
    char gate;
    char *buffer;
    struct d9_cell *cells;
    uint64_t buffer_size;
    uint64_t seed1;
    uint64_t seed2;
    uint64_t records = 0;
    uint64_t sum1 = 0;
    uint64_t sum2 = 0;
    uint64_t returned_bytes = 0;
    uint64_t syscalls = 0;
    uint64_t cell_count_u64;
    unsigned int cell_count;
    unsigned int mask;
    unsigned int mode;
    uint64_t mode_u64;
    FILE *exact_output = NULL;
    struct exact_record *exact_head = NULL;
    struct exact_record *exact_tail = NULL;
    struct timespec started;
    struct timespec finished;
    int fd;

    if (argc != 7 && argc != 8) {
        fprintf(stderr, "usage: %s DIRECTORY BUFFER_BYTES CELLS SEED1 SEED2 MODE [EXACT_OUTPUT]\n", argv[0]);
        return 2;
    }
    buffer_size = parse_u64(argv[2], "buffer size");
    cell_count_u64 = parse_u64(argv[3], "cell count");
    seed1 = parse_u64(argv[4], "seed1");
    seed2 = parse_u64(argv[5], "seed2");
    mode_u64 = parse_u64(argv[6], "mode");
    if (buffer_size < 64 || buffer_size > (1U << 24) ||
        mode_u64 > 2 ||
        cell_count_u64 < 4 || cell_count_u64 > 16384 ||
        (cell_count_u64 & (cell_count_u64 - 1))) {
        fputs("invalid buffer or cell count\n", stderr);
        return 2;
    }
    cell_count = (unsigned int)cell_count_u64;
    mode = (unsigned int)mode_u64;
    mask = cell_count - 1U;
    buffer = malloc((size_t)buffer_size);
    cells = calloc(cell_count, sizeof(*cells));
    if (!buffer || !cells) {
        fputs("allocation failed\n", stderr);
        free(buffer);
        free(cells);
        return 2;
    }
    if (argc == 8) {
        exact_output = fopen(argv[7], "wx");
        if (!exact_output) {
            perror("exact output");
            free(buffer);
            free(cells);
            return 2;
        }
    }
    if (read(STDIN_FILENO, &gate, 1) != 1) {
        fputs("failed to receive start gate\n", stderr);
        free(buffer);
        free(cells);
        return 2;
    }
    fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        free(buffer);
        free(cells);
        return 2;
    }
    clock_gettime(CLOCK_MONOTONIC, &started);
    for (;;) {
        long result = syscall(SYS_getdents64, fd, buffer, (size_t)buffer_size);
        long offset = 0;

        syscalls++;
        if (result < 0) {
            fprintf(stderr, "getdents64: %s\n", strerror(errno));
            close(fd);
            free(buffer);
            free(cells);
            return 2;
        }
        if (result == 0)
            break;
        returned_bytes += (uint64_t)result;
        usleep(1000); /* dynamic scheduling stress only */
        while (offset < result) {
            struct d9_linux_dirent64 *entry =
                (struct d9_linux_dirent64 *)(buffer + offset);
            size_t header = offsetof(struct d9_linux_dirent64, d_name);
            size_t room;
            size_t length;
            uint64_t value;
            uint64_t key_hash;
            unsigned int first;
            unsigned int second;
            unsigned int third;
            size_t index;

            if ((size_t)(result - offset) < header + 1 ||
                entry->d_reclen < header + 1 ||
                offset + entry->d_reclen > result) {
                fputs("malformed getdents64 record\n", stderr);
                close(fd);
                free(buffer);
                free(cells);
                return 2;
            }
            room = entry->d_reclen - header;
            length = strnlen(entry->d_name, room);
            if (length == room || length > 255) {
                fputs("invalid getdents64 name\n", stderr);
                close(fd);
                free(buffer);
                free(cells);
                return 2;
            }
            if (exact_output) {
                struct exact_record *record = malloc(sizeof(*record) + length);
                if (!record) {
                    fputs("exact record allocation failed\n", stderr);
                    return 2;
                }
                record->next = NULL;
                record->inode = entry->d_ino;
                record->d_type = entry->d_type;
                record->length = length;
                memcpy(record->name, entry->d_name, length);
                if (exact_tail)
                    exact_tail->next = record;
                else
                    exact_head = record;
                exact_tail = record;
            }
            records++;
            if (mode == 0) {
                offset += entry->d_reclen;
                continue;
            }
            value = d9_entry_hash_begin(seed1);
            for (index = 0; index < length; index++)
                value = d9_entry_hash_byte(
                    value, (unsigned char)entry->d_name[index]);
            key_hash = d9_entry_hash_finish(
                value, entry->d_ino, entry->d_type,
                (unsigned int)length, seed1, seed2);
            sum1 += key_hash;
            sum2 += d9_fingerprint_second(
                key_hash, entry->d_ino, entry->d_type);
            if (mode == 1) {
                offset += entry->d_reclen;
                continue;
            }
            first = d9_position_1(key_hash, seed1, mask);
            second = d9_position_2(key_hash, seed2, mask, first);
            third = d9_position_3(
                key_hash, seed1, seed2, mask, first, second);
            update_cell(cells, first, key_hash, entry->d_ino,
                        entry->d_type, seed1, seed2);
            update_cell(cells, second, key_hash, entry->d_ino,
                        entry->d_type, seed1, seed2);
            update_cell(cells, third, key_hash, entry->d_ino,
                        entry->d_type, seed1, seed2);
            offset += entry->d_reclen;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &finished);
    close(fd);
    if (exact_output) {
        int dump_error = write_exact(exact_output, exact_head);
        if (fclose(exact_output) || dump_error) {
            fputs("exact output write failed\n", stderr);
            free(buffer);
            free(cells);
            return 2;
        }
    }

    printf("{\"scan_started_ns\":%llu,\"scan_finished_ns\":%llu,",
           (unsigned long long)started.tv_sec * 1000000000ULL + started.tv_nsec,
           (unsigned long long)finished.tv_sec * 1000000000ULL + finished.tv_nsec);
    printf("\"schema_version\":1,\"mode\":%u,\"exact_capture\":%s,\"count\":%" PRIu64
           ",\"sum1\":%" PRIu64 ",\"sum2\":%" PRIu64
           ",\"syscalls\":%" PRIu64 ",\"returned_bytes\":%" PRIu64
           ",\"scan_ns\":%" PRIu64 ",\"cells\":[",
           mode, exact_output ? "true" : "false", records, sum1, sum2, syscalls, returned_bytes,
           elapsed_ns(&started, &finished));
    {
        int first_output = 1;
        unsigned int index;
        for (index = 0; index < cell_count; index++) {
            struct d9_cell *cell = &cells[index];
            if (!cell->count && !cell->key_xor && !cell->inode_xor &&
                !cell->type_xor && !cell->check_xor)
                continue;
            if (!first_output)
                putchar(',');
            first_output = 0;
            printf("[%u,%" PRId32 ",%" PRIu64 ",%" PRIu64
                   ",%" PRIu64 ",%" PRIu64 "]",
                   index, cell->count, cell->key_xor, cell->inode_xor,
                   cell->type_xor, cell->check_xor);
        }
    }
    puts("]}");
    free(buffer);
    free(cells);
    return 0;
}
