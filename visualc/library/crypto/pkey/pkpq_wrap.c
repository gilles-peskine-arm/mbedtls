#include "common.h"

#if defined(MBEDTLS_PK_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "pkpq.h"
#include "crypto_common.h"

//----------------------------------------------------------------------------
//----------------- Defines  -------------------------------------------------
//----------------------------------------------------------------------------
#define PKINFO_REGISTER_ENABLED

#ifdef PKINFO_REGISTER_ENABLED  

#define PKEY_MAX_PK_ALGORITHMS  10 
/*----------------------------------------------------------------------------*
 *----------------- static variables -----------------------------------------*
 *----------------------------------------------------------------------------*/
static pkinfo_t *pkinfo_list[PKEY_MAX_PK_ALGORITHMS]; 
static int       num_algs_registered; 

#if defined(MBEDTLS_THREADING_C)
  static mbedtls_threading_mutex_t  MBEDTLS_PRIVATE(pkinfo_mutex);
  #define pkwrap_mutex_init(b)    mbedtls_mutex_init(b)
  #define pkwrap_mutex_lock(a)    mbedtls_mutex_lock(a)
  #define pkwrap_mutex_unlock(a)  mbedtls_mutex_unlock(a)
  void __attribute__ ((constructor)) pkwrap_initialize(void) 
  { 
      pkwrap_mutex_init( &pkinfo_mutex );
      printf("%s(): Initialize mutex\n", __func__); 
  } 
#else 
  #define pkwrap_mutex_init(b)   
  #define pkwrap_mutex_lock(a)   
  #define pkwrap_mutex_unlock(a)  
#endif


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
int pkey_register_pk_algorithm( pkinfo_t * pkinfo) 
{
    int i; 
    // Add algorithm to the list

    pkwrap_mutex_lock(  &pkinfo_mutex );

    // TODO needs to be mutexed 
    for (i = 0; i < num_algs_registered; i++ )
    {
        if (pkinfo->pktype == pkinfo_list[i]->pktype) 
            goto skip_register; 
    }
    pkinfo_list[num_algs_registered++] = pkinfo; 
    LOGI("%s(): Add algorithm %d\n",__func__, (int)pkinfo->pktype); 
    pkwrap_mutex_unlock(  &pkinfo_mutex );
    return 0;  
    
skip_register: 
    LOGI("%s(): Algorithm %d already registered\n",__func__, (int)pkinfo->pktype);
    pkwrap_mutex_unlock(  &pkinfo_mutex );
    return 0;  
}

pkinfo_t *pkey_pkinfo_from_type( pktype_e  pktype )
{
    pkinfo_t *pkinfo = NULL; 
    int       i; 

    pkwrap_mutex_lock(  &pkinfo_mutex );
    for (i=0; i< num_algs_registered; i++)
    {
        pkinfo = pkinfo_list[i]; 
        if (pktype == pkinfo->pktype) 
        {
            // printf("%s(): found algorithm %d\n", __func__, pktype); 
            pkwrap_mutex_unlock(  &pkinfo_mutex );
            return pkinfo;
        }
    }
    LOGD("%s(): Failed to find algorithm %d\n", __func__, pktype); 
    pkwrap_mutex_unlock(  &pkinfo_mutex );

    // --- This section is needed to make the linker not drop the constructor functions
    pkey_rsakey_enable_constructors++;
    pkey_eckey_enable_constructors++; 
    pkey_dilkey_enable_constructors++;
    pkey_kybkey_enable_constructors++;
    return NULL;
}

#else 
/* ---------------------------------------------------------------------------
 *  Get pkinfo structure from type 
 * ---------------------------------------------------------------------------*/
pkinfo_t *pkey_pkinfo_from_type( pktype_e  pktype )
{
    // printf("%s()\n",__func__);
    switch( pktype ) {

      #if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return pkey_rsa_get_pkinfo(pktype);
      #endif
      #if defined(MBEDTLS_ECP_C) || defined (MBEDTLS_ECDSA_C) || defined (MBEDTLS_ECDSA_C) 
        case MBEDTLS_PK_ECDSA:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECKEY:
            return pkey_ec_get_pkinfo(pktype);
      #endif
      #if defined(MBEDTLS_DILITHIUM_C) 
        case MBEDTLS_PK_DILITHIUM:
            return pkey_dilithium_get_pkinfo(pktype);
        case MBEDTLS_PK_KYBER:
            return pkey_kyber_get_pkinfo(pktype);
      #endif
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
}
#endif /* PKINFO_REGISTER_ENABLED */

#endif /* MBEDTLS_PK_C */
