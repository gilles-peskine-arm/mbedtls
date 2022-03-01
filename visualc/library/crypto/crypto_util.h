/**
 * \file pkpq.h
 *
 * \brief Internal include file for the Public Key (pk) 
 *        abstraction layer with Post Quantum (pq) support.
 */

#ifndef __CRYPTO_UTIL_H__
#define __CRYPTO_UTIL_H__

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdint.h>
#include "pkey/pkpq.h"

//----------------------------------------------------------------------------
//----------------- Switches -------------------------------------------------
//----------------------------------------------------------------------------
//#define OPENSSL_FORMATTED_DUMP

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define SET_VAL_SAFE( ptr, val)  \
    if ( ptr != NULL) {          \
        *ptr = val;              \
    }

//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
void *mbed_free(void *ptr);
void *mbed_calloc(size_t nmemb, size_t size);

void  util_dump(const void *data, uint32_t length, const char *prompt);

int   util_dump2buf(const void *in, uint32_t len, char sep, size_t entry_per_line, pkbuf_t *bufout, const char *text, int dump_full); 
int   util_write_mpi_formatted( mpi_t *X, int max_len, pkbuf_t *odata, char* text);

#endif /* __CRYPTO_UTIL_H__ */
