/**
 * \file crypto_common.h
 *
 * \brief Common defines for crypto library files.
 */

#ifndef __CRYPTO_COMMON_H__
#define __CRYPTO_COMMON_H__

//----------------------------------------------------------------------------
//----------------- Includes --------------------------------------------------
//----------------------------------------------------------------------------
#include "mbedtls/error.h" 

#define LOGS_ENABLED

#ifdef MAKE_DEBUG_ENABLED
  #define LOGS_ENABLED_DEBUG 
#endif 
//--------------------------------------
//------------ Logging -----------------
//--------------------------------------
#ifndef LOGS_PREFIX
 #define LOGS_PREFIX "" 
#endif 
#ifdef LOGS_ENABLED
 #define LOGE(fmt, ...)    printf(LOGS_PREFIX"ERROR:"fmt, ##__VA_ARGS__)
 #define LOGW(fmt, ...)     printf(LOGS_PREFIX"WARN:"fmt, ##__VA_ARGS__)
 #ifdef LOGS_ENABLED_INFO
  #define LOGI(fmt, ...)    printf(LOGS_PREFIX"INFO:"fmt, ##__VA_ARGS__)
 #else
  #define LOGI(fmt, ...)
 #endif
 #ifdef LOGS_ENABLED_DEBUG
  #define LOGD(fmt, ...)    printf(LOGS_PREFIX"DEBUG:"fmt, ##__VA_ARGS__)
 #else
  #define LOGD(fmt, ...)
 #endif
#define LOGT(fmt, ...)
#else
#define LOG_ERROR(format, ...)
#define LOG_WARN(format, ...)
#define LOG_INFO(format, ...)
#define LOG_DEBUG(format, ...)
#define LOG_TRACE(format, ...)
#endif

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
#endif /* __CRYPTO_COMMON_H__ */
