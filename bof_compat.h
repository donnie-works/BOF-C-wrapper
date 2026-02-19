/**
 * bof_compat.h - BOF to Standard C Compatibility Layer
 *
 * Include this instead of bof.h to compile BOF source as a standalone executable.
 * Maps BOF-specific functions to standard C equivalents.
 *
 * Usage:
 *   #ifdef STANDALONE
 *   #include "bof_compat.h"
 *   #else
 *   #include "bof.h"
 *   #endif
 */

#ifndef BOF_COMPAT_H
#define BOF_COMPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ===========================================================================
 * String/Memory Functions - Map to standard C
 * ===========================================================================*/
#define _printf  printf
#define _sprintf sprintf
#define _malloc  malloc
#define _free    free
#define _strcmp  strcmp
#define _strcpy  strcpy
#define _strncpy strncpy
#define _strrchr strrchr
#define _strlen  strlen
#define _memcpy  memcpy
#define _memset  memset

/* ===========================================================================
 * Argument Parsing - Beacon-compatible structure and functions
 *
 * In standalone mode, we pack argv into Beacon format:
 *   [4-byte length][string data with null terminator]
 * ===========================================================================*/

typedef struct {
    char* original;
    char* current;
    int used;
    int size;
} _args;

static inline void _args_parse(_args* a, char* buf, int len) {
    a->original = buf;
    a->current = buf;
    a->used = 0;
    a->size = len;
}

static inline int _args_int(_args* a) {
    if (a->used + 4 > a->size) return 0;
    int val = *(int*)(a->current);
    a->current += 4;
    a->used += 4;
    return val;
}

static inline short _args_short(_args* a) {
    if (a->used + 2 > a->size) return 0;
    short val = *(short*)(a->current);
    a->current += 2;
    a->used += 2;
    return val;
}

static inline char* _args_str(_args* a, int* out_len) {
    if (a->used + 4 > a->size) return NULL;
    int len = *(int*)(a->current);
    a->current += 4;
    a->used += 4;

    if (a->used + len > a->size) return NULL;
    char* str = a->current;
    a->current += len;
    a->used += len;

    if (out_len) *out_len = len;
    return str;
}

static inline int _args_left(_args* a) {
    return a->size - a->used;
}

/* ===========================================================================
 * Helper: Pack argv into Beacon format for go() function
 *
 * Returns malloc'd buffer that caller must free.
 * Format: [4-byte total length][string with spaces][null]
 * ===========================================================================*/

static inline char* pack_argv(int argc, char** argv, int start_idx, int* out_len) {
    // Calculate total length
    size_t total = 0;
    for (int i = start_idx; i < argc; i++) {
        total += strlen(argv[i]);
        if (i > start_idx) total++; // space separator
    }
    total++; // null terminator

    // Allocate: 4-byte length prefix + string
    size_t buf_size = 4 + total;
    char* buf = (char*)malloc(buf_size);
    if (!buf) return NULL;

    // Write length prefix
    *(int*)buf = (int)total;

    // Concatenate args with spaces
    char* p = buf + 4;
    for (int i = start_idx; i < argc; i++) {
        if (i > start_idx) *p++ = ' ';
        size_t len = strlen(argv[i]);
        memcpy(p, argv[i], len);
        p += len;
    }
    *p = '\0';

    *out_len = (int)buf_size;
    return buf;
}

#endif /* BOF_COMPAT_H */
