/**
 * \file pkpq_parse.h
 *
 * \brief Include file for the Public Key (pk) parsing code
 */

#ifndef __PKPQ_PARSE_H__
#define __PKPQ_PARSE_H__

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "pkpq.h"

//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
int pkey_pkfull_setup( pkfull_t *pkfull, pktop_t *pktop, pktype_e pktype );

int pkey_parse_subpubkey( pkfull_t *pkfull, uint8_t **p, const uint8_t *end, size_t *der_olen ); 
int pkey_parse_pubkey_ssl( pktop_t *pktop, pktarget_e target, hybpk_t hybpk_alg, void* alg_info,  uint8_t **p, const uint8_t *end ); 


#endif // #ifndef __PKPQ_PARSE_H__

