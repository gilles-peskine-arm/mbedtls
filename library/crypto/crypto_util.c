
//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdlib.h>
#include <stdio.h>

#include "crypto_util.h"

#include "mbedtls/bignum.h"

//----------------------------------------------------------------------------
//----------------- Defines  -------------------------------------------------
//----------------------------------------------------------------------------
#define UTIL_DUMP_NRLINES_THRESH    8   // must be an even number

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------- Global functions -----------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
void *mbed_free(void *ptr) 
{
    if ( ptr != NULL)
        free(ptr);
    return NULL;
}

void *mbed_calloc(size_t nmemb, size_t size) 
{
    return calloc(nmemb, size);
}


/******************************************************************************
 * Description: print a blob of bianry data to stderr
 *
 * Arguments:   data     - pointer to the data
 *              length   - data length
 *  `           prompt   - text header for the hex dump
 *
 * result:      'short' value
 *****************************************************************************/
void util_dump(const void *data_in, uint32_t length, const char *prompt)
{
    const uint8_t  *data = (const uint8_t *)data_in; 
    unsigned int    i;

    if (prompt)
    {
        fprintf(stdout, "%s: (size=%d)  ", prompt, (int)length);
    }
    for (i = 0; i < length; ++i)
    {
        if ( (i % 32 == 0) && (length > 32) )
        {
            fprintf(stdout, "\n\t");
        }
        fprintf(stdout, "%02x, ", data[i]);
    }
    fprintf(stdout, "\n");
}

/******************************************************************************
 * Description: print a blob of binary data to stderr
 *
 * Arguments:   in       - data pointer
 *              length   - data length
 *              prompt   - text header for the hex dump
 *
 * result:      number of bytes put in the buffer 
 *****************************************************************************/
int util_dump2buf(const void *in, uint32_t len, char sep, size_t entry_per_line, pkbuf_t *result, const char *text, int dump_full)
{
    const uint8_t  *data = (const uint8_t *)in; 
    char*           indent = "    ";
    size_t          size, threshold; 
    int             i, idx=0, new_line, offset;

    /*---------------------Code ----------------------------------------------*/
    if( result == NULL)
        return 0; 
    size = result->size - 1;

    *(uint8_t*)(result->buf + size) = 0; // Null terminate    
    if (text)
        idx = snprintf((char*)result->buf, size, "%s: ", text);
    new_line = 1; 
    if ( dump_full)
        threshold = len;
    else
        threshold = UTIL_DUMP_NRLINES_THRESH * entry_per_line;
    offset = 0; 

    for (i = 0; i < (int)len; ++i)
    {
        if (i == (int)threshold)  
        {
            if ( len > threshold + threshold/2 + entry_per_line)
            {
                idx += snprintf((char*)result->buf + idx, size - idx,"\n%s...",indent);
                i = len - threshold/2;
                offset = i; 
            }
        }
        if (((i - offset) % entry_per_line == 0) && (len > entry_per_line/2)) {
            idx += snprintf((char*)result->buf + idx, size - idx,"\n%s", indent);
            new_line = 1; 
        }
        if ( new_line == 1 )
            idx += snprintf((char *)result->buf + idx, size - idx, "%02x", data[i]);
        else
            idx += snprintf((char *)result->buf + idx, size - idx, "%c%02x", sep, data[i]);
        new_line = 0; 
        if (idx >= (int)size) 
            goto finish;  // No more room in the buffer 
    }
    idx += snprintf((char*)result->buf + idx, size - idx,"\n\n");
finish: 
    result->iolen = idx; 
    return idx; 
}


/******************************************************************************
 * Description: Write an mpi formatted to a buffer 
 *
 * Arguments:   X        - multi precission integer
 *              max_len  - mpi length 
 *              odata    - container for the formatted string
 *              offset   - offset in buffer 
 *              text     - text associated with the integer
 *
 * result:      length of string returned 
 *****************************************************************************/
int util_write_mpi_formatted( mpi_t *X, int max_len, pkbuf_t *odata, char* text) 
{
    size_t  olen = 0, size; 
    int     bytes_per_line = 32;
    char    separator = ' ';

    /*---------------------Code ----------------------------------------------*/
    size = mbedtls_mpi_size(X);
  #ifdef OPENSSL_FORMATTED_DUMP
    if ( (size > 3) && (max_len == 0 ) ) 
        size += 1;
    bytes_per_line = 15; 
    separator = ':'; 
  #else 
    (void) max_len; 
  #endif 
   
    {
        uint8_t buf[size];
        mbedtls_mpi_write_binary(X, buf, size);
        olen = util_dump2buf(buf, size, separator, bytes_per_line, odata, text, 0); 
    }
    // update the odata values 
    pkbuf_move(odata, olen);
    odata->iolen += olen;
    return olen;  
}

