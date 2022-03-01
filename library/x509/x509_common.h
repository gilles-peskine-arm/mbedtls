/**
 * \file crypto_common.h
 *
 * \brief Common defines for crypto library files.
 */

#ifndef __X509_COMMON_H__
#define __X509_COMMON_H__

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#ifndef SUCCESS 
  #define SUCCESS 0 
  #define FAILURE -1 
#endif 
#ifndef TRUE 
  #define TRUE  1 
  #define FALSE 0  
#endif 


#define CHECK_FAIL( func, rc, error_label ) \
    {                                       \
        rc = func;                          \
        if (rc  != SUCCESS)                 \
            goto error_label;               \
    }  

#define LIB_ERROR  MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED

typedef unsigned int uint_t;    

//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
#endif /* __X509_COMMON_H__ */
