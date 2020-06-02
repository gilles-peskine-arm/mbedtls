/*
 *  Generic SSL/TLS messaging layer functions
 *  (record layer + retransmission state machine)
 *
 *  Copyright (C) 2006-2020, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#include "common.h"

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/version.h"

#include <string.h>

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/oid.h"
#endif

static uint32_t ssl_get_hs_total_len( mbedtls_ssl_context const *ssl );

/*
 * Start a timer.
 * Passing millisecs = 0 cancels a running timer.
 */
void mbedtls_ssl_set_timer( mbedtls_ssl_context *ssl, uint32_t millisecs )
{
    if( ssl->f_set_timer == NULL )
        return;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "set_timer to %d ms", (int) millisecs ) );
    ssl->f_set_timer( ssl->p_timer, millisecs / 4, millisecs );
}

/*
 * Return -1 is timer is expired, 0 if it isn't.
 */
int mbedtls_ssl_check_timer( mbedtls_ssl_context *ssl )
{
    if( ssl->f_get_timer == NULL )
        return( 0 );

    if( ssl->f_get_timer( ssl->p_timer ) == 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "timer expired" ) );
        return( -1 );
    }

    return( 0 );
}

#if defined(MBEDTLS_SSL_RECORD_CHECKING)
static int ssl_parse_record_header( mbedtls_ssl_context const *ssl,
                                    unsigned char *buf,
                                    size_t len,
                                    mbedtls_record *rec );

int mbedtls_ssl_check_record( mbedtls_ssl_context const *ssl,
                              unsigned char *buf,
                              size_t buflen )
{
    int ret = 0;
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "=> mbedtls_ssl_check_record" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "record buffer", buf, buflen );

    /* We don't support record checking in TLS because
     * (a) there doesn't seem to be a usecase for it, and
     * (b) In SSLv3 and TLS 1.0, CBC record decryption has state
     *     and we'd need to backup the transform here.
     */
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        goto exit;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    else
    {
        mbedtls_record rec;

        ret = ssl_parse_record_header( ssl, buf, buflen, &rec );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 3, "ssl_parse_record_header", ret );
            goto exit;
        }

        if( ssl->transform_in != NULL )
        {
            ret = mbedtls_ssl_decrypt_buf( ssl, ssl->transform_in, &rec );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 3, "mbedtls_ssl_decrypt_buf", ret );
                goto exit;
            }
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

exit:
    /* On success, we have decrypted the buffer in-place, so make
     * sure we don't leak any plaintext data. */
    mbedtls_platform_zeroize( buf, buflen );

    /* For the purpose of this API, treat messages with unexpected CID
     * as well as such from future epochs as unexpected. */
    if( ret == MBEDTLS_ERR_SSL_UNEXPECTED_CID ||
        ret == MBEDTLS_ERR_SSL_EARLY_MESSAGE )
    {
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "<= mbedtls_ssl_check_record" ) );
    return( ret );
}
#endif /* MBEDTLS_SSL_RECORD_CHECKING */

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#if defined(MBEDTLS_SSL_PROTO_DTLS)

/* Forward declarations for functions related to message buffering. */
static void ssl_buffering_free_slot( mbedtls_ssl_context *ssl,
                                     uint8_t slot );
static void ssl_free_buffered_record( mbedtls_ssl_context *ssl );
static int ssl_load_buffered_message( mbedtls_ssl_context *ssl );
static int ssl_load_buffered_record( mbedtls_ssl_context *ssl );
static int ssl_buffer_message( mbedtls_ssl_context *ssl );
static int ssl_buffer_future_record( mbedtls_ssl_context *ssl,
                                     mbedtls_record const *rec );
static int ssl_next_record_is_in_datagram( mbedtls_ssl_context *ssl );

static size_t ssl_get_maximum_datagram_size( mbedtls_ssl_context const *ssl )
{
    size_t mtu = mbedtls_ssl_get_current_mtu( ssl );
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t out_buf_len = ssl->out_buf_len;
#else
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif

    if( mtu != 0 && mtu < out_buf_len )
        return( mtu );

    return( out_buf_len );
}

static int ssl_get_remaining_space_in_datagram( mbedtls_ssl_context const *ssl )
{
    size_t const bytes_written = ssl->out_left;
    size_t const mtu           = ssl_get_maximum_datagram_size( ssl );

    /* Double-check that the write-index hasn't gone
     * past what we can transmit in a single datagram. */
    if( bytes_written > mtu )
    {
        /* Should never happen... */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( (int) ( mtu - bytes_written ) );
}

static int ssl_get_remaining_payload_in_datagram( mbedtls_ssl_context const *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t remaining, expansion;
    size_t max_len = MBEDTLS_SSL_OUT_CONTENT_LEN;

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    const size_t mfl = mbedtls_ssl_get_output_max_frag_len( ssl );

    if( max_len > mfl )
        max_len = mfl;

    /* By the standard (RFC 6066 Sect. 4), the MFL extension
     * only limits the maximum record payload size, so in theory
     * we would be allowed to pack multiple records of payload size
     * MFL into a single datagram. However, this would mean that there's
     * no way to explicitly communicate MTU restrictions to the peer.
     *
     * The following reduction of max_len makes sure that we never
     * write datagrams larger than MFL + Record Expansion Overhead.
     */
    if( max_len <= ssl->out_left )
        return( 0 );

    max_len -= ssl->out_left;
#endif

    ret = ssl_get_remaining_space_in_datagram( ssl );
    if( ret < 0 )
        return( ret );
    remaining = (size_t) ret;

    ret = mbedtls_ssl_get_record_expansion( ssl );
    if( ret < 0 )
        return( ret );
    expansion = (size_t) ret;

    if( remaining <= expansion )
        return( 0 );

    remaining -= expansion;
    if( remaining >= max_len )
        remaining = max_len;

    return( (int) remaining );
}

/*
 * Double the retransmit timeout value, within the allowed range,
 * returning -1 if the maximum value has already been reached.
 */
static int ssl_double_retransmit_timeout( mbedtls_ssl_context *ssl )
{
    uint32_t new_timeout;

    if( ssl->handshake->retransmit_timeout >= ssl->conf->hs_timeout_max )
        return( -1 );

    /* Implement the final paragraph of RFC 6347 section 4.1.1.1
     * in the following way: after the initial transmission and a first
     * retransmission, back off to a temporary estimated MTU of 508 bytes.
     * This value is guaranteed to be deliverable (if not guaranteed to be
     * delivered) of any compliant IPv4 (and IPv6) network, and should work
     * on most non-IP stacks too. */
    if( ssl->handshake->retransmit_timeout != ssl->conf->hs_timeout_min )
    {
        ssl->handshake->mtu = 508;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "mtu autoreduction to %d bytes", ssl->handshake->mtu ) );
    }

    new_timeout = 2 * ssl->handshake->retransmit_timeout;

    /* Avoid arithmetic overflow and range overflow */
    if( new_timeout < ssl->handshake->retransmit_timeout ||
        new_timeout > ssl->conf->hs_timeout_max )
    {
        new_timeout = ssl->conf->hs_timeout_max;
    }

    ssl->handshake->retransmit_timeout = new_timeout;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );

    return( 0 );
}

static void ssl_reset_retransmit_timeout( mbedtls_ssl_context *ssl )
{
    ssl->handshake->retransmit_timeout = ssl->conf->hs_timeout_min;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
int (*mbedtls_ssl_hw_record_init)( mbedtls_ssl_context *ssl,
                     const unsigned char *key_enc, const unsigned char *key_dec,
                     size_t keylen,
                     const unsigned char *iv_enc,  const unsigned char *iv_dec,
                     size_t ivlen,
                     const unsigned char *mac_enc, const unsigned char *mac_dec,
                     size_t maclen ) = NULL;
int (*mbedtls_ssl_hw_record_activate)( mbedtls_ssl_context *ssl, int direction) = NULL;
int (*mbedtls_ssl_hw_record_reset)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_write)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_read)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_finish)( mbedtls_ssl_context *ssl ) = NULL;
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

/* The function below is only used in the Lucky 13 counter-measure in
 * mbedtls_ssl_decrypt_buf(). These are the defines that guard the call site. */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC) && \
    ( defined(MBEDTLS_SSL_PROTO_TLS1) || \
      defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
      defined(MBEDTLS_SSL_PROTO_TLS1_2) )
/* This function makes sure every byte in the memory region is accessed
 * (in ascending addresses order) */
static void ssl_read_memory( unsigned char *p, size_t len )
{
    unsigned char acc = 0;
    volatile unsigned char force;

    for( ; len != 0; p++, len-- )
        acc ^= *p;

    force = acc;
    (void) force;
}
#endif /* SSL_SOME_MODES_USE_MAC && ( TLS1 || TLS1_1 || TLS1_2 ) */

/*
 * Encryption/decryption functions
 */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
/* This functions transforms a DTLS plaintext fragment and a record content
 * type into an instance of the DTLSInnerPlaintext structure:
 *
 *        struct {
 *            opaque content[DTLSPlaintext.length];
 *            ContentType real_type;
 *            uint8 zeros[length_of_padding];
 *        } DTLSInnerPlaintext;
 *
 *  Input:
 *  - `content`: The beginning of the buffer holding the
 *               plaintext to be wrapped.
 *  - `*content_size`: The length of the plaintext in Bytes.
 *  - `max_len`: The number of Bytes available starting from
 *               `content`. This must be `>= *content_size`.
 *  - `rec_type`: The desired record content type.
 *
 *  Output:
 *  - `content`: The beginning of the resulting DTLSInnerPlaintext structure.
 *  - `*content_size`: The length of the resulting DTLSInnerPlaintext structure.
 *
 *  Returns:
 *  - `0` on success.
 *  - A negative error code if `max_len` didn't offer enough space
 *    for the expansion.
 */
static int ssl_cid_build_inner_plaintext( unsigned char *content,
                                          size_t *content_size,
                                          size_t remaining,
                                          uint8_t rec_type )
{
    size_t len = *content_size;
    size_t pad = ( MBEDTLS_SSL_CID_PADDING_GRANULARITY -
                   ( len + 1 ) % MBEDTLS_SSL_CID_PADDING_GRANULARITY ) %
        MBEDTLS_SSL_CID_PADDING_GRANULARITY;

    /* Write real content type */
    if( remaining == 0 )
        return( -1 );
    content[ len ] = rec_type;
    len++;
    remaining--;

    if( remaining < pad )
        return( -1 );
    memset( content + len, 0, pad );
    len += pad;
    remaining -= pad;

    *content_size = len;
    return( 0 );
}

/* This function parses a DTLSInnerPlaintext structure.
 * See ssl_cid_build_inner_plaintext() for details. */
static int ssl_cid_parse_inner_plaintext( unsigned char const *content,
                                          size_t *content_size,
                                          uint8_t *rec_type )
{
    size_t remaining = *content_size;

    /* Determine length of padding by skipping zeroes from the back. */
    do
    {
        if( remaining == 0 )
            return( -1 );
        remaining--;
    } while( content[ remaining ] == 0 );

    *content_size = remaining;
    *rec_type = content[ remaining ];

    return( 0 );
}
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

/* `add_data` must have size 13 Bytes if the CID extension is disabled,
 * and 13 + 1 + CID-length Bytes if the CID extension is enabled. */
static void ssl_extract_add_data_from_record( unsigned char* add_data,
                                              size_t *add_data_len,
                                              mbedtls_record *rec )
{
    /* Quoting RFC 5246 (TLS 1.2):
     *
     *    additional_data = seq_num + TLSCompressed.type +
     *                      TLSCompressed.version + TLSCompressed.length;
     *
     * For the CID extension, this is extended as follows
     * (quoting draft-ietf-tls-dtls-connection-id-05,
     *  https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-05):
     *
     *       additional_data = seq_num + DTLSPlaintext.type +
     *                         DTLSPlaintext.version +
     *                         cid +
     *                         cid_length +
     *                         length_of_DTLSInnerPlaintext;
     */

    memcpy( add_data, rec->ctr, sizeof( rec->ctr ) );
    add_data[8] = rec->type;
    memcpy( add_data + 9, rec->ver, sizeof( rec->ver ) );

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if( rec->cid_len != 0 )
    {
        memcpy( add_data + 11, rec->cid, rec->cid_len );
        add_data[11 + rec->cid_len + 0] = rec->cid_len;
        add_data[11 + rec->cid_len + 1] = ( rec->data_len >> 8 ) & 0xFF;
        add_data[11 + rec->cid_len + 2] = ( rec->data_len >> 0 ) & 0xFF;
        *add_data_len = 13 + 1 + rec->cid_len;
    }
    else
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    {
        add_data[11 + 0] = ( rec->data_len >> 8 ) & 0xFF;
        add_data[11 + 1] = ( rec->data_len >> 0 ) & 0xFF;
        *add_data_len = 13;
    }
}

#if defined(MBEDTLS_SSL_PROTO_SSL3)

#define SSL3_MAC_MAX_BYTES   20  /* MD-5 or SHA-1 */

/*
 * SSLv3.0 MAC functions
 */
static void ssl_mac( mbedtls_md_context_t *md_ctx,
                     const unsigned char *secret,
                     const unsigned char *buf, size_t len,
                     const unsigned char *ctr, int type,
                     unsigned char out[SSL3_MAC_MAX_BYTES] )
{
    unsigned char header[11];
    unsigned char padding[48];
    int padlen;
    int md_size = mbedtls_md_get_size( md_ctx->md_info );
    int md_type = mbedtls_md_get_type( md_ctx->md_info );

    /* Only MD5 and SHA-1 supported */
    if( md_type == MBEDTLS_MD_MD5 )
        padlen = 48;
    else
        padlen = 40;

    memcpy( header, ctr, 8 );
    header[ 8] = (unsigned char)  type;
    header[ 9] = (unsigned char)( len >> 8 );
    header[10] = (unsigned char)( len      );

    memset( padding, 0x36, padlen );
    mbedtls_md_starts( md_ctx );
    mbedtls_md_update( md_ctx, secret,  md_size );
    mbedtls_md_update( md_ctx, padding, padlen  );
    mbedtls_md_update( md_ctx, header,  11      );
    mbedtls_md_update( md_ctx, buf,     len     );
    mbedtls_md_finish( md_ctx, out              );

    memset( padding, 0x5C, padlen );
    mbedtls_md_starts( md_ctx );
    mbedtls_md_update( md_ctx, secret,    md_size );
    mbedtls_md_update( md_ctx, padding,   padlen  );
    mbedtls_md_update( md_ctx, out,       md_size );
    mbedtls_md_finish( md_ctx, out                );
}
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

int mbedtls_ssl_encrypt_buf( mbedtls_ssl_context *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;
    unsigned char * data;
    unsigned char add_data[13 + 1 + MBEDTLS_SSL_CID_OUT_LEN_MAX ];
    size_t add_data_len;
    size_t post_avail;

    /* The SSL context is only used for debugging purposes! */
#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    /* The PRNG is used for dynamic IV generation that's used
     * for CBC transformations in TLS 1.1 and TLS 1.2. */
#if !( defined(MBEDTLS_CIPHER_MODE_CBC) &&                              \
       ( defined(MBEDTLS_AES_C)  ||                                     \
         defined(MBEDTLS_ARIA_C) ||                                     \
         defined(MBEDTLS_CAMELLIA_C) ) &&                               \
       ( defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2) ) )
    ((void) f_rng);
    ((void) p_rng);
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> encrypt buf" ) );

    if( transform == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no transform provided to encrypt_buf" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    if( rec == NULL
        || rec->buf == NULL
        || rec->buf_len < rec->data_offset
        || rec->buf_len - rec->data_offset < rec->data_len
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        || rec->cid_len != 0
#endif
        )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad record structure provided to encrypt_buf" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    data = rec->buf + rec->data_offset;
    post_avail = rec->buf_len - ( rec->data_len + rec->data_offset );
    MBEDTLS_SSL_DEBUG_BUF( 4, "before encrypt: output payload",
                           data, rec->data_len );

    mode = mbedtls_cipher_get_cipher_mode( &transform->cipher_ctx_enc );

    if( rec->data_len > MBEDTLS_SSL_OUT_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Record content %u too large, maximum %d",
                                    (unsigned) rec->data_len,
                                    MBEDTLS_SSL_OUT_CONTENT_LEN ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /*
     * Add CID information
     */
    rec->cid_len = transform->out_cid_len;
    memcpy( rec->cid, transform->out_cid, transform->out_cid_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "CID", rec->cid, rec->cid_len );

    if( rec->cid_len != 0 )
    {
        /*
         * Wrap plaintext into DTLSInnerPlaintext structure.
         * See ssl_cid_build_inner_plaintext() for more information.
         *
         * Note that this changes `rec->data_len`, and hence
         * `post_avail` needs to be recalculated afterwards.
         */
        if( ssl_cid_build_inner_plaintext( data,
                        &rec->data_len,
                        post_avail,
                        rec->type ) != 0 )
        {
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        rec->type = MBEDTLS_SSL_MSG_CID;
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    post_avail = rec->buf_len - ( rec->data_len + rec->data_offset );

    /*
     * Add MAC before if needed
     */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    if( mode == MBEDTLS_MODE_STREAM ||
        ( mode == MBEDTLS_MODE_CBC
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
          && transform->encrypt_then_mac == MBEDTLS_SSL_ETM_DISABLED
#endif
        ) )
    {
        if( post_avail < transform->maclen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer provided for encrypted record not large enough" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( transform->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            unsigned char mac[SSL3_MAC_MAX_BYTES];
            ssl_mac( &transform->md_ctx_enc, transform->mac_enc,
                     data, rec->data_len, rec->ctr, rec->type, mac );
            memcpy( data + rec->data_len, mac, transform->maclen );
        }
        else
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
        defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( transform->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
        {
            unsigned char mac[MBEDTLS_SSL_MAC_ADD];

            ssl_extract_add_data_from_record( add_data, &add_data_len, rec );

            mbedtls_md_hmac_update( &transform->md_ctx_enc, add_data,
                                    add_data_len );
            mbedtls_md_hmac_update( &transform->md_ctx_enc,
                                    data, rec->data_len );
            mbedtls_md_hmac_finish( &transform->md_ctx_enc, mac );
            mbedtls_md_hmac_reset( &transform->md_ctx_enc );

            memcpy( data + rec->data_len, mac, transform->maclen );
        }
        else
#endif
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "computed mac", data + rec->data_len,
                               transform->maclen );

        rec->data_len += transform->maclen;
        post_avail -= transform->maclen;
        auth_done++;
    }
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

    /*
     * Encrypt
     */
#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
    if( mode == MBEDTLS_MODE_STREAM )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t olen;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                                    "including %d bytes of padding",
                                    rec->data_len, 0 ) );

        if( ( ret = mbedtls_cipher_crypt( &transform->cipher_ctx_enc,
                                   transform->iv_enc, transform->ivlen,
                                   data, rec->data_len,
                                   data, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( rec->data_len != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */

#if defined(MBEDTLS_GCM_C) || \
    defined(MBEDTLS_CCM_C) || \
    defined(MBEDTLS_CHACHAPOLY_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        unsigned char iv[12];
        size_t explicit_iv_len = transform->ivlen - transform->fixed_ivlen;

        /* Check that there's space for both the authentication tag
         * and the explicit IV before and after the record content. */
        if( post_avail < transform->taglen ||
            rec->data_offset < explicit_iv_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer provided for encrypted record not large enough" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        /*
         * Generate IV
         */
        if( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
        {
            /* GCM and CCM: fixed || explicit (=seqnum) */
            memcpy( iv, transform->iv_enc, transform->fixed_ivlen );
            memcpy( iv + transform->fixed_ivlen, rec->ctr,
                    explicit_iv_len );
            /* Prefix record content with explicit IV. */
            memcpy( data - explicit_iv_len, rec->ctr, explicit_iv_len );
        }
        else if( transform->ivlen == 12 && transform->fixed_ivlen == 12 )
        {
            /* ChachaPoly: fixed XOR sequence number */
            unsigned char i;

            memcpy( iv, transform->iv_enc, transform->fixed_ivlen );

            for( i = 0; i < 8; i++ )
                iv[i+4] ^= rec->ctr[i];
        }
        else
        {
            /* Reminder if we ever add an AEAD mode with a different size */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl_extract_add_data_from_record( add_data, &add_data_len, rec );

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (internal)",
                                  iv, transform->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (transmitted)",
                                  data - explicit_iv_len, explicit_iv_len );
        MBEDTLS_SSL_DEBUG_BUF( 4, "additional data used for AEAD",
                               add_data, add_data_len );
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                                    "including 0 bytes of padding",
                                    rec->data_len ) );

        /*
         * Encrypt and authenticate
         */

        if( ( ret = mbedtls_cipher_auth_encrypt( &transform->cipher_ctx_enc,
                   iv, transform->ivlen,
                   add_data, add_data_len,       /* add data     */
                   data, rec->data_len,          /* source       */
                   data, &rec->data_len,         /* destination  */
                   data + rec->data_len, transform->taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_encrypt", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "after encrypt: tag",
                               data + rec->data_len, transform->taglen );

        rec->data_len    += transform->taglen + explicit_iv_len;
        rec->data_offset -= explicit_iv_len;
        post_avail -= transform->taglen;
        auth_done++;
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) || defined(MBEDTLS_ARIA_C) )
    if( mode == MBEDTLS_MODE_CBC )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t padlen, i;
        size_t olen;

        /* Currently we're always using minimal padding
         * (up to 255 bytes would be allowed). */
        padlen = transform->ivlen - ( rec->data_len + 1 ) % transform->ivlen;
        if( padlen == transform->ivlen )
            padlen = 0;

        /* Check there's enough space in the buffer for the padding. */
        if( post_avail < padlen + 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer provided for encrypted record not large enough" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        for( i = 0; i <= padlen; i++ )
            data[rec->data_len + i] = (unsigned char) padlen;

        rec->data_len += padlen + 1;
        post_avail -= padlen + 1;

#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
        /*
         * Prepend per-record IV for block cipher in TLS v1.1 and up as per
         * Method 1 (6.2.3.2. in RFC4346 and RFC5246)
         */
        if( transform->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            if( f_rng == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "No PRNG provided to encrypt_record routine" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            if( rec->data_offset < transform->ivlen )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer provided for encrypted record not large enough" ) );
                return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
            }

            /*
             * Generate IV
             */
            ret = f_rng( p_rng, transform->iv_enc, transform->ivlen );
            if( ret != 0 )
                return( ret );

            memcpy( data - transform->ivlen, transform->iv_enc,
                    transform->ivlen );

        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 */

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of IV and %d bytes of padding",
                            rec->data_len, transform->ivlen,
                            padlen + 1 ) );

        if( ( ret = mbedtls_cipher_crypt( &transform->cipher_ctx_enc,
                                   transform->iv_enc,
                                   transform->ivlen,
                                   data, rec->data_len,
                                   data, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( rec->data_len != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
        if( transform->minor_ver < MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1
             */
            memcpy( transform->iv_enc, transform->cipher_ctx_enc.iv,
                    transform->ivlen );
        }
        else
#endif
        {
            data             -= transform->ivlen;
            rec->data_offset -= transform->ivlen;
            rec->data_len    += transform->ivlen;
        }

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        if( auth_done == 0 )
        {
            unsigned char mac[MBEDTLS_SSL_MAC_ADD];

            /*
             * MAC(MAC_write_key, seq_num +
             *     TLSCipherText.type +
             *     TLSCipherText.version +
             *     length_of( (IV +) ENC(...) ) +
             *     IV + // except for TLS 1.0
             *     ENC(content + padding + padding_length));
             */

            if( post_avail < transform->maclen)
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer provided for encrypted record not large enough" ) );
                return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
            }

            ssl_extract_add_data_from_record( add_data, &add_data_len, rec );

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );
            MBEDTLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", add_data,
                                   add_data_len );

            mbedtls_md_hmac_update( &transform->md_ctx_enc, add_data,
                                    add_data_len );
            mbedtls_md_hmac_update( &transform->md_ctx_enc,
                                    data, rec->data_len );
            mbedtls_md_hmac_finish( &transform->md_ctx_enc, mac );
            mbedtls_md_hmac_reset( &transform->md_ctx_enc );

            memcpy( data + rec->data_len, mac, transform->maclen );

            rec->data_len += transform->maclen;
            post_avail -= transform->maclen;
            auth_done++;
        }
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */
    }
    else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C || MBEDTLS_ARIA_C ) */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= encrypt buf" ) );

    return( 0 );
}

int mbedtls_ssl_decrypt_buf( mbedtls_ssl_context const *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec )
{
    size_t olen;
    mbedtls_cipher_mode_t mode;
    int ret, auth_done = 0;
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    size_t padlen = 0, correct = 1;
#endif
    unsigned char* data;
    unsigned char add_data[13 + 1 + MBEDTLS_SSL_CID_IN_LEN_MAX ];
    size_t add_data_len;

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> decrypt buf" ) );
    if( rec == NULL                     ||
        rec->buf == NULL                ||
        rec->buf_len < rec->data_offset ||
        rec->buf_len - rec->data_offset < rec->data_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad record structure provided to decrypt_buf" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    data = rec->buf + rec->data_offset;
    mode = mbedtls_cipher_get_cipher_mode( &transform->cipher_ctx_dec );

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /*
     * Match record's CID with incoming CID.
     */
    if( rec->cid_len != transform->in_cid_len ||
        memcmp( rec->cid, transform->in_cid, rec->cid_len ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_UNEXPECTED_CID );
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
    if( mode == MBEDTLS_MODE_STREAM )
    {
        padlen = 0;
        if( ( ret = mbedtls_cipher_crypt( &transform->cipher_ctx_dec,
                                   transform->iv_dec,
                                   transform->ivlen,
                                   data, rec->data_len,
                                   data, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( rec->data_len != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */
#if defined(MBEDTLS_GCM_C) || \
    defined(MBEDTLS_CCM_C) || \
    defined(MBEDTLS_CHACHAPOLY_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        unsigned char iv[12];
        size_t explicit_iv_len = transform->ivlen - transform->fixed_ivlen;

        /*
         * Prepare IV from explicit and implicit data.
         */

        /* Check that there's enough space for the explicit IV
         * (at the beginning of the record) and the MAC (at the
         * end of the record). */
        if( rec->data_len < explicit_iv_len + transform->taglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < explicit_iv_len (%d) "
                                        "+ taglen (%d)", rec->data_len,
                                        explicit_iv_len, transform->taglen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C)
        if( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
        {
            /* GCM and CCM: fixed || explicit */

            /* Fixed */
            memcpy( iv, transform->iv_dec, transform->fixed_ivlen );
            /* Explicit */
            memcpy( iv + transform->fixed_ivlen, data, 8 );
        }
        else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CHACHAPOLY_C)
        if( transform->ivlen == 12 && transform->fixed_ivlen == 12 )
        {
            /* ChachaPoly: fixed XOR sequence number */
            unsigned char i;

            memcpy( iv, transform->iv_dec, transform->fixed_ivlen );

            for( i = 0; i < 8; i++ )
                iv[i+4] ^= rec->ctr[i];
        }
        else
#endif /* MBEDTLS_CHACHAPOLY_C */
        {
            /* Reminder if we ever add an AEAD mode with a different size */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /* Group changes to data, data_len, and add_data, because
         * add_data depends on data_len. */
        data += explicit_iv_len;
        rec->data_offset += explicit_iv_len;
        rec->data_len -= explicit_iv_len + transform->taglen;

        ssl_extract_add_data_from_record( add_data, &add_data_len, rec );
        MBEDTLS_SSL_DEBUG_BUF( 4, "additional data used for AEAD",
                               add_data, add_data_len );

        /* Because of the check above, we know that there are
         * explicit_iv_len Bytes preceeding data, and taglen
         * bytes following data + data_len. This justifies
         * the debug message and the invocation of
         * mbedtls_cipher_auth_decrypt() below. */

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used", iv, transform->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "TAG used", data + rec->data_len,
                               transform->taglen );

        /*
         * Decrypt and authenticate
         */
        if( ( ret = mbedtls_cipher_auth_decrypt( &transform->cipher_ctx_dec,
                  iv, transform->ivlen,
                  add_data, add_data_len,
                  data, rec->data_len,
                  data, &olen,
                  data + rec->data_len,
                  transform->taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_decrypt", ret );

            if( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED )
                return( MBEDTLS_ERR_SSL_INVALID_MAC );

            return( ret );
        }
        auth_done++;

        /* Double-check that AEAD decryption doesn't change content length. */
        if( olen != rec->data_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) || defined(MBEDTLS_ARIA_C) )
    if( mode == MBEDTLS_MODE_CBC )
    {
        size_t minlen = 0;

        /*
         * Check immediate ciphertext sanity
         */
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( transform->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /* The ciphertext is prefixed with the CBC IV. */
            minlen += transform->ivlen;
        }
#endif

        /* Size considerations:
         *
         * - The CBC cipher text must not be empty and hence
         *   at least of size transform->ivlen.
         *
         * Together with the potential IV-prefix, this explains
         * the first of the two checks below.
         *
         * - The record must contain a MAC, either in plain or
         *   encrypted, depending on whether Encrypt-then-MAC
         *   is used or not.
         *   - If it is, the message contains the IV-prefix,
         *     the CBC ciphertext, and the MAC.
         *   - If it is not, the padded plaintext, and hence
         *     the CBC ciphertext, has at least length maclen + 1
         *     because there is at least the padding length byte.
         *
         * As the CBC ciphertext is not empty, both cases give the
         * lower bound minlen + maclen + 1 on the record size, which
         * we test for in the second check below.
         */
        if( rec->data_len < minlen + transform->ivlen ||
            rec->data_len < minlen + transform->maclen + 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < max( ivlen(%d), maclen (%d) "
                                "+ 1 ) ( + expl IV )", rec->data_len,
                                transform->ivlen,
                                transform->maclen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }

        /*
         * Authenticate before decrypt if enabled
         */
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        if( transform->encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED )
        {
            unsigned char mac_expect[MBEDTLS_SSL_MAC_ADD];

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );

            /* Update data_len in tandem with add_data.
             *
             * The subtraction is safe because of the previous check
             * data_len >= minlen + maclen + 1.
             *
             * Afterwards, we know that data + data_len is followed by at
             * least maclen Bytes, which justifies the call to
             * mbedtls_ssl_safer_memcmp() below.
             *
             * Further, we still know that data_len > minlen */
            rec->data_len -= transform->maclen;
            ssl_extract_add_data_from_record( add_data, &add_data_len, rec );

            /* Calculate expected MAC. */
            MBEDTLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", add_data,
                                   add_data_len );
            mbedtls_md_hmac_update( &transform->md_ctx_dec, add_data,
                                    add_data_len );
            mbedtls_md_hmac_update( &transform->md_ctx_dec,
                                    data, rec->data_len );
            mbedtls_md_hmac_finish( &transform->md_ctx_dec, mac_expect );
            mbedtls_md_hmac_reset( &transform->md_ctx_dec );

            MBEDTLS_SSL_DEBUG_BUF( 4, "message  mac", data + rec->data_len,
                                   transform->maclen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "expected mac", mac_expect,
                                   transform->maclen );

            /* Compare expected MAC with MAC at the end of the record. */
            if( mbedtls_ssl_safer_memcmp( data + rec->data_len, mac_expect,
                                          transform->maclen ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );
                return( MBEDTLS_ERR_SSL_INVALID_MAC );
            }
            auth_done++;
        }
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */

        /*
         * Check length sanity
         */

        /* We know from above that data_len > minlen >= 0,
         * so the following check in particular implies that
         * data_len >= minlen + ivlen ( = minlen or 2 * minlen ). */
        if( rec->data_len % transform->ivlen != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) %% ivlen (%d) != 0",
                                        rec->data_len, transform->ivlen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }

#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
        /*
         * Initialize for prepended IV for block cipher in TLS v1.1 and up
         */
        if( transform->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /* Safe because data_len >= minlen + ivlen = 2 * ivlen. */
            memcpy( transform->iv_dec, data, transform->ivlen );

            data += transform->ivlen;
            rec->data_offset += transform->ivlen;
            rec->data_len -= transform->ivlen;
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 */

        /* We still have data_len % ivlen == 0 and data_len >= ivlen here. */

        if( ( ret = mbedtls_cipher_crypt( &transform->cipher_ctx_dec,
                                   transform->iv_dec, transform->ivlen,
                                   data, rec->data_len, data, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        /* Double-check that length hasn't changed during decryption. */
        if( rec->data_len != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
        if( transform->minor_ver < MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1, where CBC decryption of consecutive
             * records is equivalent to CBC decryption of the concatenation
             * of the records; in other words, IVs are maintained across
             * record decryptions.
             */
            memcpy( transform->iv_dec, transform->cipher_ctx_dec.iv,
                    transform->ivlen );
        }
#endif

        /* Safe since data_len >= minlen + maclen + 1, so after having
         * subtracted at most minlen and maclen up to this point,
         * data_len > 0 (because of data_len % ivlen == 0, it's actually
         * >= ivlen ). */
        padlen = data[rec->data_len - 1];

        if( auth_done == 1 )
        {
            correct *= ( rec->data_len >= padlen + 1 );
            padlen  *= ( rec->data_len >= padlen + 1 );
        }
        else
        {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
            if( rec->data_len < transform->maclen + padlen + 1 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < maclen (%d) + padlen (%d)",
                                            rec->data_len,
                                            transform->maclen,
                                            padlen + 1 ) );
            }
#endif

            correct *= ( rec->data_len >= transform->maclen + padlen + 1 );
            padlen  *= ( rec->data_len >= transform->maclen + padlen + 1 );
        }

        padlen++;

        /* Regardless of the validity of the padding,
         * we have data_len >= padlen here. */

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( transform->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            if( padlen > transform->ivlen )
            {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad padding length: is %d, "
                                            "should be no more than %d",
                                            padlen, transform->ivlen ) );
#endif
                correct = 0;
            }
        }
        else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( transform->minor_ver > MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            /* The padding check involves a series of up to 256
             * consecutive memory reads at the end of the record
             * plaintext buffer. In order to hide the length and
             * validity of the padding, always perform exactly
             * `min(256,plaintext_len)` reads (but take into account
             * only the last `padlen` bytes for the padding check). */
            size_t pad_count = 0;
            size_t real_count = 0;
            volatile unsigned char* const check = data;

            /* Index of first padding byte; it has been ensured above
             * that the subtraction is safe. */
            size_t const padding_idx = rec->data_len - padlen;
            size_t const num_checks = rec->data_len <= 256 ? rec->data_len : 256;
            size_t const start_idx = rec->data_len - num_checks;
            size_t idx;

            for( idx = start_idx; idx < rec->data_len; idx++ )
            {
                real_count |= ( idx >= padding_idx );
                pad_count += real_count * ( check[idx] == padlen - 1 );
            }
            correct &= ( pad_count == padlen );

#if defined(MBEDTLS_SSL_DEBUG_ALL)
            if( padlen > 0 && correct == 0 )
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad padding byte detected" ) );
#endif
            padlen &= correct * 0x1FF;
        }
        else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
          MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /* If the padding was found to be invalid, padlen == 0
         * and the subtraction is safe. If the padding was found valid,
         * padlen hasn't been changed and the previous assertion
         * data_len >= padlen still holds. */
        rec->data_len -= padlen;
    }
    else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C || MBEDTLS_ARIA_C ) */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_DEBUG_ALL)
    MBEDTLS_SSL_DEBUG_BUF( 4, "raw buffer after decryption",
                           data, rec->data_len );
#endif

    /*
     * Authenticate if not done yet.
     * Compute the MAC regardless of the padding result (RFC4346, CBCTIME).
     */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    if( auth_done == 0 )
    {
        unsigned char mac_expect[MBEDTLS_SSL_MAC_ADD];

        /* If the initial value of padlen was such that
         * data_len < maclen + padlen + 1, then padlen
         * got reset to 1, and the initial check
         * data_len >= minlen + maclen + 1
         * guarantees that at this point we still
         * have at least data_len >= maclen.
         *
         * If the initial value of padlen was such that
         * data_len >= maclen + padlen + 1, then we have
         * subtracted either padlen + 1 (if the padding was correct)
         * or 0 (if the padding was incorrect) since then,
         * hence data_len >= maclen in any case.
         */
        rec->data_len -= transform->maclen;
        ssl_extract_add_data_from_record( add_data, &add_data_len, rec );

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( transform->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            ssl_mac( &transform->md_ctx_dec,
                     transform->mac_dec,
                     data, rec->data_len,
                     rec->ctr, rec->type,
                     mac_expect );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
        defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( transform->minor_ver > MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            /*
             * Process MAC and always update for padlen afterwards to make
             * total time independent of padlen.
             *
             * Known timing attacks:
             *  - Lucky Thirteen (http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
             *
             * To compensate for different timings for the MAC calculation
             * depending on how much padding was removed (which is determined
             * by padlen), process extra_run more blocks through the hash
             * function.
             *
             * The formula in the paper is
             *   extra_run = ceil( (L1-55) / 64 ) - ceil( (L2-55) / 64 )
             * where L1 is the size of the header plus the decrypted message
             * plus CBC padding and L2 is the size of the header plus the
             * decrypted message. This is for an underlying hash function
             * with 64-byte blocks.
             * We use ( (Lx+8) / 64 ) to handle 'negative Lx' values
             * correctly. We round down instead of up, so -56 is the correct
             * value for our calculations instead of -55.
             *
             * Repeat the formula rather than defining a block_size variable.
             * This avoids requiring division by a variable at runtime
             * (which would be marginally less efficient and would require
             * linking an extra division function in some builds).
             */
            size_t j, extra_run = 0;
            unsigned char tmp[MBEDTLS_MD_MAX_BLOCK_SIZE];

            /*
             * The next two sizes are the minimum and maximum values of
             * in_msglen over all padlen values.
             *
             * They're independent of padlen, since we previously did
             * data_len -= padlen.
             *
             * Note that max_len + maclen is never more than the buffer
             * length, as we previously did in_msglen -= maclen too.
             */
            const size_t max_len = rec->data_len + padlen;
            const size_t min_len = ( max_len > 256 ) ? max_len - 256 : 0;

            memset( tmp, 0, sizeof( tmp ) );

            switch( mbedtls_md_get_type( transform->md_ctx_dec.md_info ) )
            {
#if defined(MBEDTLS_MD5_C) || defined(MBEDTLS_SHA1_C) || \
    defined(MBEDTLS_SHA256_C)
                case MBEDTLS_MD_MD5:
                case MBEDTLS_MD_SHA1:
                case MBEDTLS_MD_SHA256:
                    /* 8 bytes of message size, 64-byte compression blocks */
                    extra_run =
                        ( add_data_len + rec->data_len + padlen + 8 ) / 64 -
                        ( add_data_len + rec->data_len          + 8 ) / 64;
                    break;
#endif
#if defined(MBEDTLS_SHA512_C)
                case MBEDTLS_MD_SHA384:
                    /* 16 bytes of message size, 128-byte compression blocks */
                    extra_run =
                        ( add_data_len + rec->data_len + padlen + 16 ) / 128 -
                        ( add_data_len + rec->data_len          + 16 ) / 128;
                    break;
#endif
                default:
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            extra_run &= correct * 0xFF;

            mbedtls_md_hmac_update( &transform->md_ctx_dec, add_data,
                                    add_data_len );
            mbedtls_md_hmac_update( &transform->md_ctx_dec, data,
                                    rec->data_len );
            /* Make sure we access everything even when padlen > 0. This
             * makes the synchronisation requirements for just-in-time
             * Prime+Probe attacks much tighter and hopefully impractical. */
            ssl_read_memory( data + rec->data_len, padlen );
            mbedtls_md_hmac_finish( &transform->md_ctx_dec, mac_expect );

            /* Call mbedtls_md_process at least once due to cache attacks
             * that observe whether md_process() was called of not */
            for( j = 0; j < extra_run + 1; j++ )
                mbedtls_md_process( &transform->md_ctx_dec, tmp );

            mbedtls_md_hmac_reset( &transform->md_ctx_dec );

            /* Make sure we access all the memory that could contain the MAC,
             * before we check it in the next code block. This makes the
             * synchronisation requirements for just-in-time Prime+Probe
             * attacks much tighter and hopefully impractical. */
            ssl_read_memory( data + min_len,
                             max_len - min_len + transform->maclen );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
              MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(MBEDTLS_SSL_DEBUG_ALL)
        MBEDTLS_SSL_DEBUG_BUF( 4, "expected mac", mac_expect, transform->maclen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "message  mac", data + rec->data_len, transform->maclen );
#endif

        if( mbedtls_ssl_safer_memcmp( data + rec->data_len, mac_expect,
                                      transform->maclen ) != 0 )
        {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );
#endif
            correct = 0;
        }
        auth_done++;
    }

    /*
     * Finally check the correct flag
     */
    if( correct == 0 )
        return( MBEDTLS_ERR_SSL_INVALID_MAC );
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if( rec->cid_len != 0 )
    {
        ret = ssl_cid_parse_inner_plaintext( data, &rec->data_len,
                                             &rec->type );
        if( ret != 0 )
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= decrypt buf" ) );

    return( 0 );
}

#undef MAC_NONE
#undef MAC_PLAINTEXT
#undef MAC_CIPHERTEXT

#if defined(MBEDTLS_ZLIB_SUPPORT)
/*
 * Compression/decompression functions
 */
static int ssl_compress_buf( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *msg_post = ssl->out_msg;
    ptrdiff_t bytes_written = ssl->out_msg - ssl->out_buf;
    size_t len_pre = ssl->out_msglen;
    unsigned char *msg_pre = ssl->compress_buf;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t out_buf_len = ssl->out_buf_len;
#else
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> compress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->out_msg, len_pre );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "before compression: msglen = %d, ",
                   ssl->out_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "before compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    ssl->transform_out->ctx_deflate.next_in = msg_pre;
    ssl->transform_out->ctx_deflate.avail_in = len_pre;
    ssl->transform_out->ctx_deflate.next_out = msg_post;
    ssl->transform_out->ctx_deflate.avail_out = out_buf_len - bytes_written;

    ret = deflate( &ssl->transform_out->ctx_deflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "failed to perform compression (%d)", ret ) );
        return( MBEDTLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->out_msglen = out_buf_len -
                      ssl->transform_out->ctx_deflate.avail_out - bytes_written;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "after compression: msglen = %d, ",
                   ssl->out_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "after compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= compress buf" ) );

    return( 0 );
}

static int ssl_decompress_buf( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *msg_post = ssl->in_msg;
    ptrdiff_t header_bytes = ssl->in_msg - ssl->in_buf;
    size_t len_pre = ssl->in_msglen;
    unsigned char *msg_pre = ssl->compress_buf;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t in_buf_len = ssl->in_buf_len;
#else
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> decompress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->in_msg, len_pre );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "before decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "before decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    ssl->transform_in->ctx_inflate.next_in = msg_pre;
    ssl->transform_in->ctx_inflate.avail_in = len_pre;
    ssl->transform_in->ctx_inflate.next_out = msg_post;
    ssl->transform_in->ctx_inflate.avail_out = in_buf_len - header_bytes;

    ret = inflate( &ssl->transform_in->ctx_inflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "failed to perform decompression (%d)", ret ) );
        return( MBEDTLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->in_msglen = in_buf_len -
                     ssl->transform_in->ctx_inflate.avail_out - header_bytes;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "after decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "after decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= decompress buf" ) );

    return( 0 );
}
#endif /* MBEDTLS_ZLIB_SUPPORT */

/*
 * Fill the input message buffer by appending data to it.
 * The amount of data already fetched is in ssl->in_left.
 *
 * If we return 0, is it guaranteed that (at least) nb_want bytes are
 * available (from this read and/or a previous one). Otherwise, an error code
 * is returned (possibly EOF or WANT_READ).
 *
 * With stream transport (TLS) on success ssl->in_left == nb_want, but
 * with datagram transport (DTLS) on success ssl->in_left >= nb_want,
 * since we always read a whole datagram at once.
 *
 * For DTLS, it is up to the caller to set ssl->next_record_offset when
 * they're done reading a record.
 */
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t in_buf_len = ssl->in_buf_len;
#else
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> fetch input" ) );

    if( ssl->f_recv == NULL && ssl->f_recv_timeout == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Bad usage of mbedtls_ssl_set_bio() "
                            "or mbedtls_ssl_set_bio()" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( nb_want > in_buf_len - (size_t)( ssl->in_hdr - ssl->in_buf ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "requesting more data than fits" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        uint32_t timeout;

        /* Just to be sure */
        if( ssl->f_set_timer == NULL || ssl->f_get_timer == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "You must use "
                        "mbedtls_ssl_set_timer_cb() for DTLS" ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }

        /*
         * The point is, we need to always read a full datagram at once, so we
         * sometimes read more then requested, and handle the additional data.
         * It could be the rest of the current record (while fetching the
         * header) and/or some other records in the same datagram.
         */

        /*
         * Move to the next record in the already read datagram if applicable
         */
        if( ssl->next_record_offset != 0 )
        {
            if( ssl->in_left < ssl->next_record_offset )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            ssl->in_left -= ssl->next_record_offset;

            if( ssl->in_left != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "next record in same datagram, offset: %d",
                                    ssl->next_record_offset ) );
                memmove( ssl->in_hdr,
                         ssl->in_hdr + ssl->next_record_offset,
                         ssl->in_left );
            }

            ssl->next_record_offset = 0;
        }

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        /*
         * Done if we already have enough data.
         */
        if( nb_want <= ssl->in_left)
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= fetch input" ) );
            return( 0 );
        }

        /*
         * A record can't be split across datagrams. If we need to read but
         * are not at the beginning of a new record, the caller did something
         * wrong.
         */
        if( ssl->in_left != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /*
         * Don't even try to read if time's out already.
         * This avoids by-passing the timer when repeatedly receiving messages
         * that will end up being dropped.
         */
        if( mbedtls_ssl_check_timer( ssl ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "timer has expired" ) );
            ret = MBEDTLS_ERR_SSL_TIMEOUT;
        }
        else
        {
            len = in_buf_len - ( ssl->in_hdr - ssl->in_buf );

            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
                timeout = ssl->handshake->retransmit_timeout;
            else
                timeout = ssl->conf->read_timeout;

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "f_recv_timeout: %u ms", timeout ) );

            if( ssl->f_recv_timeout != NULL )
                ret = ssl->f_recv_timeout( ssl->p_bio, ssl->in_hdr, len,
                                                                    timeout );
            else
                ret = ssl->f_recv( ssl->p_bio, ssl->in_hdr, len );

            MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( MBEDTLS_ERR_SSL_CONN_EOF );
        }

        if( ret == MBEDTLS_ERR_SSL_TIMEOUT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "timeout" ) );
            mbedtls_ssl_set_timer( ssl, 0 );

            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                if( ssl_double_retransmit_timeout( ssl ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake timeout" ) );
                    return( MBEDTLS_ERR_SSL_TIMEOUT );
                }

                if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend", ret );
                    return( ret );
                }

                return( MBEDTLS_ERR_SSL_WANT_READ );
            }
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
            else if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                     ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
            {
                if( ( ret = mbedtls_ssl_resend_hello_request( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend_hello_request",
                                           ret );
                    return( ret );
                }

                return( MBEDTLS_ERR_SSL_WANT_READ );
            }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */
        }

        if( ret < 0 )
            return( ret );

        ssl->in_left = ret;
    }
    else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        while( ssl->in_left < nb_want )
        {
            len = nb_want - ssl->in_left;

            if( mbedtls_ssl_check_timer( ssl ) != 0 )
                ret = MBEDTLS_ERR_SSL_TIMEOUT;
            else
            {
                if( ssl->f_recv_timeout != NULL )
                {
                    ret = ssl->f_recv_timeout( ssl->p_bio,
                                               ssl->in_hdr + ssl->in_left, len,
                                               ssl->conf->read_timeout );
                }
                else
                {
                    ret = ssl->f_recv( ssl->p_bio,
                                       ssl->in_hdr + ssl->in_left, len );
                }
            }

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                                        ssl->in_left, nb_want ) );
            MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( MBEDTLS_ERR_SSL_CONN_EOF );

            if( ret < 0 )
                return( ret );

            if ( (size_t)ret > len || ( INT_MAX > SIZE_MAX && ret > SIZE_MAX ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1,
                    ( "f_recv returned %d bytes but only %lu were requested",
                    ret, (unsigned long)len ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            ssl->in_left += ret;
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= fetch input" ) );

    return( 0 );
}

/*
 * Flush any data not yet written
 */
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> flush output" ) );

    if( ssl->f_send == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Bad usage of mbedtls_ssl_set_bio() "
                            "or mbedtls_ssl_set_bio()" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /* Avoid incrementing counter if data is flushed */
    if( ssl->out_left == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= flush output" ) );
        return( 0 );
    }

    while( ssl->out_left > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "message length: %d, out_left: %d",
                       mbedtls_ssl_out_hdr_len( ssl ) + ssl->out_msglen, ssl->out_left ) );

        buf = ssl->out_hdr - ssl->out_left;
        ret = ssl->f_send( ssl->p_bio, buf, ssl->out_left );

        MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_send", ret );

        if( ret <= 0 )
            return( ret );

        if( (size_t)ret > ssl->out_left || ( INT_MAX > SIZE_MAX && ret > SIZE_MAX ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1,
                ( "f_send returned %d bytes but only %lu bytes were sent",
                ret, (unsigned long)ssl->out_left ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_left -= ret;
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_hdr = ssl->out_buf;
    }
    else
#endif
    {
        ssl->out_hdr = ssl->out_buf + 8;
    }
    mbedtls_ssl_update_out_pointers( ssl, ssl->transform_out );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= flush output" ) );

    return( 0 );
}

/*
 * Functions to handle the DTLS retransmission state machine
 */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * Append current handshake message to current outgoing flight
 */
static int ssl_flight_append( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_flight_item *msg;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> ssl_flight_append" ) );
    MBEDTLS_SSL_DEBUG_BUF( 4, "message appended to flight",
                           ssl->out_msg, ssl->out_msglen );

    /* Allocate space for current message */
    if( ( msg = mbedtls_calloc( 1, sizeof(  mbedtls_ssl_flight_item ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed",
                            sizeof( mbedtls_ssl_flight_item ) ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    if( ( msg->p = mbedtls_calloc( 1, ssl->out_msglen ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed", ssl->out_msglen ) );
        mbedtls_free( msg );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    /* Copy current handshake message with headers */
    memcpy( msg->p, ssl->out_msg, ssl->out_msglen );
    msg->len = ssl->out_msglen;
    msg->type = ssl->out_msgtype;
    msg->next = NULL;

    /* Append to the current flight */
    if( ssl->handshake->flight == NULL )
        ssl->handshake->flight = msg;
    else
    {
        mbedtls_ssl_flight_item *cur = ssl->handshake->flight;
        while( cur->next != NULL )
            cur = cur->next;
        cur->next = msg;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= ssl_flight_append" ) );
    return( 0 );
}

/*
 * Free the current flight of handshake messages
 */
void mbedtls_ssl_flight_free( mbedtls_ssl_flight_item *flight )
{
    mbedtls_ssl_flight_item *cur = flight;
    mbedtls_ssl_flight_item *next;

    while( cur != NULL )
    {
        next = cur->next;

        mbedtls_free( cur->p );
        mbedtls_free( cur );

        cur = next;
    }
}

/*
 * Swap transform_out and out_ctr with the alternative ones
 */
static int ssl_swap_epochs( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_transform *tmp_transform;
    unsigned char tmp_out_ctr[8];

    if( ssl->transform_out == ssl->handshake->alt_transform_out )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "skip swap epochs" ) );
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "swap epochs" ) );

    /* Swap transforms */
    tmp_transform                     = ssl->transform_out;
    ssl->transform_out                = ssl->handshake->alt_transform_out;
    ssl->handshake->alt_transform_out = tmp_transform;

    /* Swap epoch + sequence_number */
    memcpy( tmp_out_ctr,                 ssl->cur_out_ctr,            8 );
    memcpy( ssl->cur_out_ctr,            ssl->handshake->alt_out_ctr, 8 );
    memcpy( ssl->handshake->alt_out_ctr, tmp_out_ctr,                 8 );

    /* Adjust to the newly activated transform */
    mbedtls_ssl_update_out_pointers( ssl, ssl->transform_out );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        int ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_OUTBOUND );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

    return( 0 );
}

/*
 * Retransmit the current flight of messages.
 */
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_resend" ) );

    ret = mbedtls_ssl_flight_transmit( ssl );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_resend" ) );

    return( ret );
}

/*
 * Transmit or retransmit the current flight of messages.
 *
 * Need to remember the current message in case flush_output returns
 * WANT_WRITE, causing us to exit this function and come back later.
 * This function must be called until state is no longer SENDING.
 */
int mbedtls_ssl_flight_transmit( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_flight_transmit" ) );

    if( ssl->handshake->retransmit_state != MBEDTLS_SSL_RETRANS_SENDING )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "initialise flight transmission" ) );

        ssl->handshake->cur_msg = ssl->handshake->flight;
        ssl->handshake->cur_msg_p = ssl->handshake->flight->p + 12;
        ret = ssl_swap_epochs( ssl );
        if( ret != 0 )
            return( ret );

        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_SENDING;
    }

    while( ssl->handshake->cur_msg != NULL )
    {
        size_t max_frag_len;
        const mbedtls_ssl_flight_item * const cur = ssl->handshake->cur_msg;

        int const is_finished =
            ( cur->type == MBEDTLS_SSL_MSG_HANDSHAKE &&
              cur->p[0] == MBEDTLS_SSL_HS_FINISHED );

        uint8_t const force_flush = ssl->disable_datagram_packing == 1 ?
            SSL_FORCE_FLUSH : SSL_DONT_FORCE_FLUSH;

        /* Swap epochs before sending Finished: we can't do it after
         * sending ChangeCipherSpec, in case write returns WANT_READ.
         * Must be done before copying, may change out_msg pointer */
        if( is_finished && ssl->handshake->cur_msg_p == ( cur->p + 12 ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "swap epochs to send finished message" ) );
            ret = ssl_swap_epochs( ssl );
            if( ret != 0 )
                return( ret );
        }

        ret = ssl_get_remaining_payload_in_datagram( ssl );
        if( ret < 0 )
            return( ret );
        max_frag_len = (size_t) ret;

        /* CCS is copied as is, while HS messages may need fragmentation */
        if( cur->type == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
        {
            if( max_frag_len == 0 )
            {
                if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
                    return( ret );

                continue;
            }

            memcpy( ssl->out_msg, cur->p, cur->len );
            ssl->out_msglen  = cur->len;
            ssl->out_msgtype = cur->type;

            /* Update position inside current message */
            ssl->handshake->cur_msg_p += cur->len;
        }
        else
        {
            const unsigned char * const p = ssl->handshake->cur_msg_p;
            const size_t hs_len = cur->len - 12;
            const size_t frag_off = p - ( cur->p + 12 );
            const size_t rem_len = hs_len - frag_off;
            size_t cur_hs_frag_len, max_hs_frag_len;

            if( ( max_frag_len < 12 ) || ( max_frag_len == 12 && hs_len != 0 ) )
            {
                if( is_finished )
                {
                    ret = ssl_swap_epochs( ssl );
                    if( ret != 0 )
                        return( ret );
                }

                if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
                    return( ret );

                continue;
            }
            max_hs_frag_len = max_frag_len - 12;

            cur_hs_frag_len = rem_len > max_hs_frag_len ?
                max_hs_frag_len : rem_len;

            if( frag_off == 0 && cur_hs_frag_len != hs_len )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "fragmenting handshake message (%u > %u)",
                                            (unsigned) cur_hs_frag_len,
                                            (unsigned) max_hs_frag_len ) );
            }

            /* Messages are stored with handshake headers as if not fragmented,
             * copy beginning of headers then fill fragmentation fields.
             * Handshake headers: type(1) len(3) seq(2) f_off(3) f_len(3) */
            memcpy( ssl->out_msg, cur->p, 6 );

            ssl->out_msg[6] = ( ( frag_off >> 16 ) & 0xff );
            ssl->out_msg[7] = ( ( frag_off >>  8 ) & 0xff );
            ssl->out_msg[8] = ( ( frag_off       ) & 0xff );

            ssl->out_msg[ 9] = ( ( cur_hs_frag_len >> 16 ) & 0xff );
            ssl->out_msg[10] = ( ( cur_hs_frag_len >>  8 ) & 0xff );
            ssl->out_msg[11] = ( ( cur_hs_frag_len       ) & 0xff );

            MBEDTLS_SSL_DEBUG_BUF( 3, "handshake header", ssl->out_msg, 12 );

            /* Copy the handshake message content and set records fields */
            memcpy( ssl->out_msg + 12, p, cur_hs_frag_len );
            ssl->out_msglen = cur_hs_frag_len + 12;
            ssl->out_msgtype = cur->type;

            /* Update position inside current message */
            ssl->handshake->cur_msg_p += cur_hs_frag_len;
        }

        /* If done with the current message move to the next one if any */
        if( ssl->handshake->cur_msg_p >= cur->p + cur->len )
        {
            if( cur->next != NULL )
            {
                ssl->handshake->cur_msg = cur->next;
                ssl->handshake->cur_msg_p = cur->next->p + 12;
            }
            else
            {
                ssl->handshake->cur_msg = NULL;
                ssl->handshake->cur_msg_p = NULL;
            }
        }

        /* Actually send the message out */
        if( ( ret = mbedtls_ssl_write_record( ssl, force_flush ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
            return( ret );
        }
    }

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    /* Update state and set timer */
    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    else
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
        mbedtls_ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_flight_transmit" ) );

    return( 0 );
}

/*
 * To be called when the last message of an incoming flight is received.
 */
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl )
{
    /* We won't need to resend that one any more */
    mbedtls_ssl_flight_free( ssl->handshake->flight );
    ssl->handshake->flight = NULL;
    ssl->handshake->cur_msg = NULL;

    /* The next incoming flight will start with this msg_seq */
    ssl->handshake->in_flight_start_seq = ssl->handshake->in_msg_seq;

    /* We don't want to remember CCS's across flight boundaries. */
    ssl->handshake->buffering.seen_ccs = 0;

    /* Clear future message buffering structure. */
    mbedtls_ssl_buffering_free( ssl );

    /* Cancel timer */
    mbedtls_ssl_set_timer( ssl, 0 );

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_PREPARING;
}

/*
 * To be called when the last message of an outgoing flight is send.
 */
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl )
{
    ssl_reset_retransmit_timeout( ssl );
    mbedtls_ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

/*
 * Handshake layer functions
 */

/*
 * Write (DTLS: or queue) current handshake (including CCS) message.
 *
 *  - fill in handshake headers
 *  - update handshake checksum
 *  - DTLS: save message for resending
 *  - then pass to the record layer
 *
 * DTLS: except for HelloRequest, messages are only queued, and will only be
 * actually sent when calling flight_transmit() or resend().
 *
 * Inputs:
 *  - ssl->out_msglen: 4 + actual handshake message len
 *      (4 is the size of handshake headers for TLS)
 *  - ssl->out_msg[0]: the handshake type (ClientHello, ServerHello, etc)
 *  - ssl->out_msg + 4: the handshake message body
 *
 * Outputs, ie state before passing to flight_append() or write_record():
 *   - ssl->out_msglen: the length of the record contents
 *      (including handshake headers but excluding record headers)
 *   - ssl->out_msg: the record contents (handshake headers + content)
 */
int mbedtls_ssl_write_handshake_msg( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t hs_len = ssl->out_msglen - 4;
    const unsigned char hs_type = ssl->out_msg[0];

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write handshake message" ) );

    /*
     * Sanity checks
     */
    if( ssl->out_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE          &&
        ssl->out_msgtype != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        /* In SSLv3, the client might send a NoCertificate alert. */
#if defined(MBEDTLS_SSL_PROTO_SSL3) && defined(MBEDTLS_SSL_CLI_C)
        if( ! ( ssl->minor_ver      == MBEDTLS_SSL_MINOR_VERSION_0 &&
                ssl->out_msgtype    == MBEDTLS_SSL_MSG_ALERT       &&
                ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) )
#endif /* MBEDTLS_SSL_PROTO_SSL3 && MBEDTLS_SSL_SRV_C */
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }

    /* Whenever we send anything different from a
     * HelloRequest we should be in a handshake - double check. */
    if( ! ( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
            hs_type          == MBEDTLS_SSL_HS_HELLO_REQUEST ) &&
        ssl->handshake == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
#endif

    /* Double-check that we did not exceed the bounds
     * of the outgoing record buffer.
     * This should never fail as the various message
     * writing functions must obey the bounds of the
     * outgoing record buffer, but better be safe.
     *
     * Note: We deliberately do not check for the MTU or MFL here.
     */
    if( ssl->out_msglen > MBEDTLS_SSL_OUT_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Record too large: "
                                    "size %u, maximum %u",
                                    (unsigned) ssl->out_msglen,
                                    (unsigned) MBEDTLS_SSL_OUT_CONTENT_LEN ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Fill handshake headers
     */
    if( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        ssl->out_msg[1] = (unsigned char)( hs_len >> 16 );
        ssl->out_msg[2] = (unsigned char)( hs_len >>  8 );
        ssl->out_msg[3] = (unsigned char)( hs_len       );

        /*
         * DTLS has additional fields in the Handshake layer,
         * between the length field and the actual payload:
         *      uint16 message_seq;
         *      uint24 fragment_offset;
         *      uint24 fragment_length;
         */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Make room for the additional DTLS fields */
            if( MBEDTLS_SSL_OUT_CONTENT_LEN - ssl->out_msglen < 8 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "DTLS handshake message too large: "
                              "size %u, maximum %u",
                               (unsigned) ( hs_len ),
                               (unsigned) ( MBEDTLS_SSL_OUT_CONTENT_LEN - 12 ) ) );
                return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
            }

            memmove( ssl->out_msg + 12, ssl->out_msg + 4, hs_len );
            ssl->out_msglen += 8;

            /* Write message_seq and update it, except for HelloRequest */
            if( hs_type != MBEDTLS_SSL_HS_HELLO_REQUEST )
            {
                ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                ssl->out_msg[5] = ( ssl->handshake->out_msg_seq      ) & 0xFF;
                ++( ssl->handshake->out_msg_seq );
            }
            else
            {
                ssl->out_msg[4] = 0;
                ssl->out_msg[5] = 0;
            }

            /* Handshake hashes are computed without fragmentation,
             * so set frag_offset = 0 and frag_len = hs_len for now */
            memset( ssl->out_msg + 6, 0x00, 3 );
            memcpy( ssl->out_msg + 9, ssl->out_msg + 1, 3 );
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        /* Update running hashes of handshake messages seen */
        if( hs_type != MBEDTLS_SSL_HS_HELLO_REQUEST )
            ssl->handshake->update_checksum( ssl, ssl->out_msg, ssl->out_msglen );
    }

    /* Either send now, or just save to be sent (and resent) later */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ! ( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
            hs_type          == MBEDTLS_SSL_HS_HELLO_REQUEST ) )
    {
        if( ( ret = ssl_flight_append( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_flight_append", ret );
            return( ret );
        }
    }
    else
#endif
    {
        if( ( ret = mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_record", ret );
            return( ret );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write handshake message" ) );

    return( 0 );
}

/*
 * Record layer functions
 */

/*
 * Write current record.
 *
 * Uses:
 *  - ssl->out_msgtype: type of the message (AppData, Handshake, Alert, CCS)
 *  - ssl->out_msglen: length of the record content (excl headers)
 *  - ssl->out_msg: record content
 */
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl, uint8_t force_flush )
{
    int ret, done = 0;
    size_t len = ssl->out_msglen;
    uint8_t flush = force_flush;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write record" ) );

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->transform_out != NULL &&
        ssl->session_out->compression == MBEDTLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_compress_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_compress_buf", ret );
            return( ret );
        }

        len = ssl->out_msglen;
    }
#endif /*MBEDTLS_ZLIB_SUPPORT */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_write != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_write()" ) );

        ret = mbedtls_ssl_hw_record_write( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_write", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */
    if( !done )
    {
        unsigned i;
        size_t protected_record_size;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t out_buf_len = ssl->out_buf_len;
#else
        size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif
        /* Skip writing the record content type to after the encryption,
         * as it may change when using the CID extension. */

        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, ssl->out_hdr + 1 );

        memcpy( ssl->out_ctr, ssl->cur_out_ctr, 8 );
        ssl->out_len[0] = (unsigned char)( len >> 8 );
        ssl->out_len[1] = (unsigned char)( len      );

        if( ssl->transform_out != NULL )
        {
            mbedtls_record rec;

            rec.buf         = ssl->out_iv;
            rec.buf_len     = out_buf_len - ( ssl->out_iv - ssl->out_buf );
            rec.data_len    = ssl->out_msglen;
            rec.data_offset = ssl->out_msg - rec.buf;

            memcpy( &rec.ctr[0], ssl->out_ctr, 8 );
            mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                                       ssl->conf->transport, rec.ver );
            rec.type = ssl->out_msgtype;

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            /* The CID is set by mbedtls_ssl_encrypt_buf(). */
            rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

            if( ( ret = mbedtls_ssl_encrypt_buf( ssl, ssl->transform_out, &rec,
                                         ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
                return( ret );
            }

            if( rec.data_offset != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            /* Update the record content type and CID. */
            ssl->out_msgtype = rec.type;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID )
            memcpy( ssl->out_cid, rec.cid, rec.cid_len );
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
            ssl->out_msglen = len = rec.data_len;
            ssl->out_len[0] = (unsigned char)( rec.data_len >> 8 );
            ssl->out_len[1] = (unsigned char)( rec.data_len      );
        }

        protected_record_size = len + mbedtls_ssl_out_hdr_len( ssl );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* In case of DTLS, double-check that we don't exceed
         * the remaining space in the datagram. */
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            ret = ssl_get_remaining_space_in_datagram( ssl );
            if( ret < 0 )
                return( ret );

            if( protected_record_size > (size_t) ret )
            {
                /* Should never happen */
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        /* Now write the potentially updated record content type. */
        ssl->out_hdr[0] = (unsigned char) ssl->out_msgtype;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                                    "version = [%d:%d], msglen = %d",
                                    ssl->out_hdr[0], ssl->out_hdr[1],
                                    ssl->out_hdr[2], len ) );

        MBEDTLS_SSL_DEBUG_BUF( 4, "output record sent to network",
                               ssl->out_hdr, protected_record_size );

        ssl->out_left += protected_record_size;
        ssl->out_hdr  += protected_record_size;
        mbedtls_ssl_update_out_pointers( ssl, ssl->transform_out );

        for( i = 8; i > mbedtls_ssl_ep_len( ssl ); i-- )
            if( ++ssl->cur_out_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == mbedtls_ssl_ep_len( ssl ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "outgoing message counter would wrap" ) );
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        flush == SSL_DONT_FORCE_FLUSH )
    {
        size_t remaining;
        ret = ssl_get_remaining_payload_in_datagram( ssl );
        if( ret < 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_get_remaining_payload_in_datagram",
                                   ret );
            return( ret );
        }

        remaining = (size_t) ret;
        if( remaining == 0 )
        {
            flush = SSL_FORCE_FLUSH;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "Still %u bytes available in current datagram", (unsigned) remaining ) );
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    if( ( flush == SSL_FORCE_FLUSH ) &&
        ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write record" ) );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)

static int ssl_hs_is_proper_fragment( mbedtls_ssl_context *ssl )
{
    if( ssl->in_msglen < ssl->in_hslen ||
        memcmp( ssl->in_msg + 6, "\0\0\0",        3 ) != 0 ||
        memcmp( ssl->in_msg + 9, ssl->in_msg + 1, 3 ) != 0 )
    {
        return( 1 );
    }
    return( 0 );
}

static uint32_t ssl_get_hs_frag_len( mbedtls_ssl_context const *ssl )
{
    return( ( ssl->in_msg[9] << 16  ) |
            ( ssl->in_msg[10] << 8  ) |
              ssl->in_msg[11] );
}

static uint32_t ssl_get_hs_frag_off( mbedtls_ssl_context const *ssl )
{
    return( ( ssl->in_msg[6] << 16 ) |
            ( ssl->in_msg[7] << 8  ) |
              ssl->in_msg[8] );
}

static int ssl_check_hs_header( mbedtls_ssl_context const *ssl )
{
    uint32_t msg_len, frag_off, frag_len;

    msg_len  = ssl_get_hs_total_len( ssl );
    frag_off = ssl_get_hs_frag_off( ssl );
    frag_len = ssl_get_hs_frag_len( ssl );

    if( frag_off > msg_len )
        return( -1 );

    if( frag_len > msg_len - frag_off )
        return( -1 );

    if( frag_len + 12 > ssl->in_msglen )
        return( -1 );

    return( 0 );
}

/*
 * Mark bits in bitmask (used for DTLS HS reassembly)
 */
static void ssl_bitmask_set( unsigned char *mask, size_t offset, size_t len )
{
    unsigned int start_bits, end_bits;

    start_bits = 8 - ( offset % 8 );
    if( start_bits != 8 )
    {
        size_t first_byte_idx = offset / 8;

        /* Special case */
        if( len <= start_bits )
        {
            for( ; len != 0; len-- )
                mask[first_byte_idx] |= 1 << ( start_bits - len );

            /* Avoid potential issues with offset or len becoming invalid */
            return;
        }

        offset += start_bits; /* Now offset % 8 == 0 */
        len -= start_bits;

        for( ; start_bits != 0; start_bits-- )
            mask[first_byte_idx] |= 1 << ( start_bits - 1 );
    }

    end_bits = len % 8;
    if( end_bits != 0 )
    {
        size_t last_byte_idx = ( offset + len ) / 8;

        len -= end_bits; /* Now len % 8 == 0 */

        for( ; end_bits != 0; end_bits-- )
            mask[last_byte_idx] |= 1 << ( 8 - end_bits );
    }

    memset( mask + offset / 8, 0xFF, len / 8 );
}

/*
 * Check that bitmask is full
 */
static int ssl_bitmask_check( unsigned char *mask, size_t len )
{
    size_t i;

    for( i = 0; i < len / 8; i++ )
        if( mask[i] != 0xFF )
            return( -1 );

    for( i = 0; i < len % 8; i++ )
        if( ( mask[len / 8] & ( 1 << ( 7 - i ) ) ) == 0 )
            return( -1 );

    return( 0 );
}

/* msg_len does not include the handshake header */
static size_t ssl_get_reassembly_buffer_size( size_t msg_len,
                                              unsigned add_bitmap )
{
    size_t alloc_len;

    alloc_len  = 12;                                 /* Handshake header */
    alloc_len += msg_len;                            /* Content buffer   */

    if( add_bitmap )
        alloc_len += msg_len / 8 + ( msg_len % 8 != 0 ); /* Bitmap       */

    return( alloc_len );
}

#endif /* MBEDTLS_SSL_PROTO_DTLS */

static uint32_t ssl_get_hs_total_len( mbedtls_ssl_context const *ssl )
{
    return( ( ssl->in_msg[1] << 16 ) |
            ( ssl->in_msg[2] << 8  ) |
              ssl->in_msg[3] );
}

int mbedtls_ssl_prepare_handshake_record( mbedtls_ssl_context *ssl )
{
    if( ssl->in_msglen < mbedtls_ssl_hs_hdr_len( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake message too short: %d",
                            ssl->in_msglen ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    ssl->in_hslen = mbedtls_ssl_hs_hdr_len( ssl ) + ssl_get_hs_total_len( ssl );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "handshake message: msglen ="
                        " %d, type = %d, hslen = %d",
                        ssl->in_msglen, ssl->in_msg[0], ssl->in_hslen ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        unsigned int recv_msg_seq = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];

        if( ssl_check_hs_header( ssl ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid handshake header" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->handshake != NULL &&
            ( ( ssl->state   != MBEDTLS_SSL_HANDSHAKE_OVER &&
                recv_msg_seq != ssl->handshake->in_msg_seq ) ||
              ( ssl->state  == MBEDTLS_SSL_HANDSHAKE_OVER &&
                ssl->in_msg[0] != MBEDTLS_SSL_HS_CLIENT_HELLO ) ) )
        {
            if( recv_msg_seq > ssl->handshake->in_msg_seq )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "received future handshake message of sequence number %u (next %u)",
                                            recv_msg_seq,
                                            ssl->handshake->in_msg_seq ) );
                return( MBEDTLS_ERR_SSL_EARLY_MESSAGE );
            }

            /* Retransmit only on last message from previous flight, to avoid
             * too many retransmissions.
             * Besides, No sane server ever retransmits HelloVerifyRequest */
            if( recv_msg_seq == ssl->handshake->in_flight_start_seq - 1 &&
                ssl->in_msg[0] != MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "received message from last flight, "
                                    "message_seq = %d, start_of_flight = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_flight_start_seq ) );

                if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend", ret );
                    return( ret );
                }
            }
            else
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "dropping out-of-sequence message: "
                                    "message_seq = %d, expected = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_msg_seq ) );
            }

            return( MBEDTLS_ERR_SSL_CONTINUE_PROCESSING );
        }
        /* Wait until message completion to increment in_msg_seq */

        /* Message reassembly is handled alongside buffering of future
         * messages; the commonality is that both handshake fragments and
         * future messages cannot be forwarded immediately to the
         * handshake logic layer. */
        if( ssl_hs_is_proper_fragment( ssl ) == 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "found fragmented DTLS handshake message" ) );
            return( MBEDTLS_ERR_SSL_EARLY_MESSAGE );
        }
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    /* With TLS we don't handle fragmentation (for now) */
    if( ssl->in_msglen < ssl->in_hslen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS handshake fragmentation not supported" ) );
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}

void mbedtls_ssl_update_handshake_status( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER && hs != NULL )
    {
        ssl->handshake->update_checksum( ssl, ssl->in_msg, ssl->in_hslen );
    }

    /* Handshake message is complete, increment counter */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL )
    {
        unsigned offset;
        mbedtls_ssl_hs_buffer *hs_buf;

        /* Increment handshake sequence number */
        hs->in_msg_seq++;

        /*
         * Clear up handshake buffering and reassembly structure.
         */

        /* Free first entry */
        ssl_buffering_free_slot( ssl, 0 );

        /* Shift all other entries */
        for( offset = 0, hs_buf = &hs->buffering.hs[0];
             offset + 1 < MBEDTLS_SSL_MAX_BUFFERED_HS;
             offset++, hs_buf++ )
        {
            *hs_buf = *(hs_buf + 1);
        }

        /* Create a fresh last entry */
        memset( hs_buf, 0, sizeof( mbedtls_ssl_hs_buffer ) );
    }
#endif
}

/*
 * DTLS anti-replay: RFC 6347 4.1.2.6
 *
 * in_window is a field of bits numbered from 0 (lsb) to 63 (msb).
 * Bit n is set iff record number in_window_top - n has been seen.
 *
 * Usually, in_window_top is the last record number seen and the lsb of
 * in_window is set. The only exception is the initial state (record number 0
 * not seen yet).
 */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_dtls_replay_reset( mbedtls_ssl_context *ssl )
{
    ssl->in_window_top = 0;
    ssl->in_window = 0;
}

static inline uint64_t ssl_load_six_bytes( unsigned char *buf )
{
    return( ( (uint64_t) buf[0] << 40 ) |
            ( (uint64_t) buf[1] << 32 ) |
            ( (uint64_t) buf[2] << 24 ) |
            ( (uint64_t) buf[3] << 16 ) |
            ( (uint64_t) buf[4] <<  8 ) |
            ( (uint64_t) buf[5]       ) );
}

static int mbedtls_ssl_dtls_record_replay_check( mbedtls_ssl_context *ssl, uint8_t *record_in_ctr )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *original_in_ctr;

    // save original in_ctr
    original_in_ctr = ssl->in_ctr;

    // use counter from record
    ssl->in_ctr = record_in_ctr;

    ret = mbedtls_ssl_dtls_replay_check( (mbedtls_ssl_context const *) ssl );

    // restore the counter
    ssl->in_ctr = original_in_ctr;

    return ret;
}

/*
 * Return 0 if sequence number is acceptable, -1 otherwise
 */
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context const *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );
    uint64_t bit;

    if( ssl->conf->anti_replay == MBEDTLS_SSL_ANTI_REPLAY_DISABLED )
        return( 0 );

    if( rec_seqnum > ssl->in_window_top )
        return( 0 );

    bit = ssl->in_window_top - rec_seqnum;

    if( bit >= 64 )
        return( -1 );

    if( ( ssl->in_window & ( (uint64_t) 1 << bit ) ) != 0 )
        return( -1 );

    return( 0 );
}

/*
 * Update replay window on new validated record
 */
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );

    if( ssl->conf->anti_replay == MBEDTLS_SSL_ANTI_REPLAY_DISABLED )
        return;

    if( rec_seqnum > ssl->in_window_top )
    {
        /* Update window_top and the contents of the window */
        uint64_t shift = rec_seqnum - ssl->in_window_top;

        if( shift >= 64 )
            ssl->in_window = 1;
        else
        {
            ssl->in_window <<= shift;
            ssl->in_window |= 1;
        }

        ssl->in_window_top = rec_seqnum;
    }
    else
    {
        /* Mark that number as seen in the current window */
        uint64_t bit = ssl->in_window_top - rec_seqnum;

        if( bit < 64 ) /* Always true, but be extra sure */
            ssl->in_window |= (uint64_t) 1 << bit;
    }
}
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
/*
 * Without any SSL context, check if a datagram looks like a ClientHello with
 * a valid cookie, and if it doesn't, generate a HelloVerifyRequest message.
 * Both input and output include full DTLS headers.
 *
 * - if cookie is valid, return 0
 * - if ClientHello looks superficially valid but cookie is not,
 *   fill obuf and set olen, then
 *   return MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED
 * - otherwise return a specific error code
 */
static int ssl_check_dtls_clihlo_cookie(
                           mbedtls_ssl_cookie_write_t *f_cookie_write,
                           mbedtls_ssl_cookie_check_t *f_cookie_check,
                           void *p_cookie,
                           const unsigned char *cli_id, size_t cli_id_len,
                           const unsigned char *in, size_t in_len,
                           unsigned char *obuf, size_t buf_len, size_t *olen )
{
    size_t sid_len, cookie_len;
    unsigned char *p;

    /*
     * Structure of ClientHello with record and handshake headers,
     * and expected values. We don't need to check a lot, more checks will be
     * done when actually parsing the ClientHello - skipping those checks
     * avoids code duplication and does not make cookie forging any easier.
     *
     *  0-0  ContentType type;                  copied, must be handshake
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied, must be 0
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     (ignored)
     *
     * 13-13 HandshakeType msg_type;            (ignored)
     * 14-16 uint24 length;                     (ignored)
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied, must be 0
     * 22-24 uint24 fragment_length;            (ignored)
     *
     * 25-26 ProtocolVersion client_version;    (ignored)
     * 27-58 Random random;                     (ignored)
     * 59-xx SessionID session_id;              1 byte len + sid_len content
     * 60+   opaque cookie<0..2^8-1>;           1 byte len + content
     *       ...
     *
     * Minimum length is 61 bytes.
     */
    if( in_len < 61 ||
        in[0] != MBEDTLS_SSL_MSG_HANDSHAKE ||
        in[3] != 0 || in[4] != 0 ||
        in[19] != 0 || in[20] != 0 || in[21] != 0 )
    {
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    sid_len = in[59];
    if( sid_len > in_len - 61 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    cookie_len = in[60 + sid_len];
    if( cookie_len > in_len - 60 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    if( f_cookie_check( p_cookie, in + sid_len + 61, cookie_len,
                        cli_id, cli_id_len ) == 0 )
    {
        /* Valid cookie */
        return( 0 );
    }

    /*
     * If we get here, we've got an invalid cookie, let's prepare HVR.
     *
     *  0-0  ContentType type;                  copied
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     olen - 13
     *
     * 13-13 HandshakeType msg_type;            hello_verify_request
     * 14-16 uint24 length;                     olen - 25
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied
     * 22-24 uint24 fragment_length;            olen - 25
     *
     * 25-26 ProtocolVersion server_version;    0xfe 0xff
     * 27-27 opaque cookie<0..2^8-1>;           cookie_len = olen - 27, cookie
     *
     * Minimum length is 28.
     */
    if( buf_len < 28 )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Copy most fields and adapt others */
    memcpy( obuf, in, 25 );
    obuf[13] = MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST;
    obuf[25] = 0xfe;
    obuf[26] = 0xff;

    /* Generate and write actual cookie */
    p = obuf + 28;
    if( f_cookie_write( p_cookie,
                        &p, obuf + buf_len, cli_id, cli_id_len ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    *olen = p - obuf;

    /* Go back and fill length fields */
    obuf[27] = (unsigned char)( *olen - 28 );

    obuf[14] = obuf[22] = (unsigned char)( ( *olen - 25 ) >> 16 );
    obuf[15] = obuf[23] = (unsigned char)( ( *olen - 25 ) >>  8 );
    obuf[16] = obuf[24] = (unsigned char)( ( *olen - 25 )       );

    obuf[11] = (unsigned char)( ( *olen - 13 ) >>  8 );
    obuf[12] = (unsigned char)( ( *olen - 13 )       );

    return( MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED );
}

/*
 * Handle possible client reconnect with the same UDP quadruplet
 * (RFC 6347 Section 4.2.8).
 *
 * Called by ssl_parse_record_header() in case we receive an epoch 0 record
 * that looks like a ClientHello.
 *
 * - if the input looks like a ClientHello without cookies,
 *   send back HelloVerifyRequest, then return 0
 * - if the input looks like a ClientHello with a valid cookie,
 *   reset the session of the current context, and
 *   return MBEDTLS_ERR_SSL_CLIENT_RECONNECT
 * - if anything goes wrong, return a specific error code
 *
 * This function is called (through ssl_check_client_reconnect()) when an
 * unexpected record is found in ssl_get_next_record(), which will discard the
 * record if we return 0, and bubble up the return value otherwise (this
 * includes the case of MBEDTLS_ERR_SSL_CLIENT_RECONNECT and of unexpected
 * errors, and is the right thing to do in both cases).
 */
static int ssl_handle_possible_reconnect( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if( ssl->conf->f_cookie_write == NULL ||
        ssl->conf->f_cookie_check == NULL )
    {
        /* If we can't use cookies to verify reachability of the peer,
         * drop the record. */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no cookie callbacks, "
                                    "can't check reconnect validity" ) );
        return( 0 );
    }

    ret = ssl_check_dtls_clihlo_cookie(
            ssl->conf->f_cookie_write,
            ssl->conf->f_cookie_check,
            ssl->conf->p_cookie,
            ssl->cli_id, ssl->cli_id_len,
            ssl->in_buf, ssl->in_left,
            ssl->out_buf, MBEDTLS_SSL_OUT_CONTENT_LEN, &len );

    MBEDTLS_SSL_DEBUG_RET( 2, "ssl_check_dtls_clihlo_cookie", ret );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        int send_ret;
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "sending HelloVerifyRequest" ) );
        MBEDTLS_SSL_DEBUG_BUF( 4, "output record sent to network",
                                  ssl->out_buf, len );
        /* Don't check write errors as we can't do anything here.
         * If the error is permanent we'll catch it later,
         * if it's not, then hopefully it'll work next time. */
        send_ret = ssl->f_send( ssl->p_bio, ssl->out_buf, len );
        MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_send", send_ret );
        (void) send_ret;

        return( 0 );
    }

    if( ret == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cookie is valid, resetting context" ) );
        if( ( ret = mbedtls_ssl_session_reset_int( ssl, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "reset", ret );
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_CLIENT_RECONNECT );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE && MBEDTLS_SSL_SRV_C */

static int ssl_check_record_type( uint8_t record_type )
{
    if( record_type != MBEDTLS_SSL_MSG_HANDSHAKE &&
        record_type != MBEDTLS_SSL_MSG_ALERT &&
        record_type != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
        record_type != MBEDTLS_SSL_MSG_APPLICATION_DATA )
    {
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    return( 0 );
}

/*
 * ContentType type;
 * ProtocolVersion version;
 * uint16 epoch;            // DTLS only
 * uint48 sequence_number;  // DTLS only
 * uint16 length;
 *
 * Return 0 if header looks sane (and, for DTLS, the record is expected)
 * MBEDTLS_ERR_SSL_INVALID_RECORD if the header looks bad,
 * MBEDTLS_ERR_SSL_UNEXPECTED_RECORD (DTLS only) if sane but unexpected.
 *
 * With DTLS, mbedtls_ssl_read_record() will:
 * 1. proceed with the record if this function returns 0
 * 2. drop only the current record if this function returns UNEXPECTED_RECORD
 * 3. return CLIENT_RECONNECT if this function return that value
 * 4. drop the whole datagram if this function returns anything else.
 * Point 2 is needed when the peer is resending, and we have already received
 * the first record from a datagram but are still waiting for the others.
 */
static int ssl_parse_record_header( mbedtls_ssl_context const *ssl,
                                    unsigned char *buf,
                                    size_t len,
                                    mbedtls_record *rec )
{
    int major_ver, minor_ver;

    size_t const rec_hdr_type_offset    = 0;
    size_t const rec_hdr_type_len       = 1;

    size_t const rec_hdr_version_offset = rec_hdr_type_offset +
                                          rec_hdr_type_len;
    size_t const rec_hdr_version_len    = 2;

    size_t const rec_hdr_ctr_len        = 8;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint32_t     rec_epoch;
    size_t const rec_hdr_ctr_offset     = rec_hdr_version_offset +
                                          rec_hdr_version_len;

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    size_t const rec_hdr_cid_offset     = rec_hdr_ctr_offset +
                                          rec_hdr_ctr_len;
    size_t       rec_hdr_cid_len        = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    size_t       rec_hdr_len_offset; /* To be determined */
    size_t const rec_hdr_len_len    = 2;

    /*
     * Check minimum lengths for record header.
     */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        rec_hdr_len_offset = rec_hdr_ctr_offset + rec_hdr_ctr_len;
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        rec_hdr_len_offset = rec_hdr_version_offset + rec_hdr_version_len;
    }

    if( len < rec_hdr_len_offset + rec_hdr_len_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "datagram of length %u too small to hold DTLS record header of length %u",
                 (unsigned) len,
                 (unsigned)( rec_hdr_len_len + rec_hdr_len_len ) ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    /*
     * Parse and validate record content type
     */

    rec->type = buf[ rec_hdr_type_offset ];

    /* Check record content type */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    rec->cid_len = 0;

    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->conf->cid_len != 0                                &&
        rec->type == MBEDTLS_SSL_MSG_CID )
    {
        /* Shift pointers to account for record header including CID
         * struct {
         *   ContentType special_type = tls12_cid;
         *   ProtocolVersion version;
         *   uint16 epoch;
         *   uint48 sequence_number;
         *   opaque cid[cid_length]; // Additional field compared to
         *                           // default DTLS record format
         *   uint16 length;
         *   opaque enc_content[DTLSCiphertext.length];
         * } DTLSCiphertext;
         */

        /* So far, we only support static CID lengths
         * fixed in the configuration. */
        rec_hdr_cid_len = ssl->conf->cid_len;
        rec_hdr_len_offset += rec_hdr_cid_len;

        if( len < rec_hdr_len_offset + rec_hdr_len_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "datagram of length %u too small to hold DTLS record header including CID, length %u",
                (unsigned) len,
                (unsigned)( rec_hdr_len_offset + rec_hdr_len_len ) ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        /* configured CID len is guaranteed at most 255, see
         * MBEDTLS_SSL_CID_OUT_LEN_MAX in check_config.h */
        rec->cid_len = (uint8_t) rec_hdr_cid_len;
        memcpy( rec->cid, buf + rec_hdr_cid_offset, rec_hdr_cid_len );
    }
    else
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    {
        if( ssl_check_record_type( rec->type ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "unknown record type %u",
                                        (unsigned) rec->type ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }

    /*
     * Parse and validate record version
     */

    rec->ver[0] = buf[ rec_hdr_version_offset + 0 ];
    rec->ver[1] = buf[ rec_hdr_version_offset + 1 ];
    mbedtls_ssl_read_version( &major_ver, &minor_ver,
                              ssl->conf->transport,
                              &rec->ver[0] );

    if( major_ver != ssl->major_ver )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "major version mismatch" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    if( minor_ver > ssl->conf->max_minor_ver )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "minor version mismatch" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    /*
     * Parse/Copy record sequence number.
     */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Copy explicit record sequence number from input buffer. */
        memcpy( &rec->ctr[0], buf + rec_hdr_ctr_offset,
                rec_hdr_ctr_len );
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        /* Copy implicit record sequence number from SSL context structure. */
        memcpy( &rec->ctr[0], ssl->in_ctr, rec_hdr_ctr_len );
    }

    /*
     * Parse record length.
     */

    rec->data_offset = rec_hdr_len_offset + rec_hdr_len_len;
    rec->data_len    = ( (size_t) buf[ rec_hdr_len_offset + 0 ] << 8 ) |
                       ( (size_t) buf[ rec_hdr_len_offset + 1 ] << 0 );
    MBEDTLS_SSL_DEBUG_BUF( 4, "input record header", buf, rec->data_offset );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "input record: msgtype = %d, "
                                "version = [%d:%d], msglen = %d",
                                rec->type,
                                major_ver, minor_ver, rec->data_len ) );

    rec->buf     = buf;
    rec->buf_len = rec->data_offset + rec->data_len;

    if( rec->data_len == 0 )
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );

    /*
     * DTLS-related tests.
     * Check epoch before checking length constraint because
     * the latter varies with the epoch. E.g., if a ChangeCipherSpec
     * message gets duplicated before the corresponding Finished message,
     * the second ChangeCipherSpec should be discarded because it belongs
     * to an old epoch, but not because its length is shorter than
     * the minimum record length for packets using the new record transform.
     * Note that these two kinds of failures are handled differently,
     * as an unexpected record is silently skipped but an invalid
     * record leads to the entire datagram being dropped.
     */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        rec_epoch = ( rec->ctr[0] << 8 ) | rec->ctr[1];

        /* Check that the datagram is large enough to contain a record
         * of the advertised length. */
        if( len < rec->data_offset + rec->data_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Datagram of length %u too small to contain record of advertised length %u.",
                             (unsigned) len,
                             (unsigned)( rec->data_offset + rec->data_len ) ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        /* Records from other, non-matching epochs are silently discarded.
         * (The case of same-port Client reconnects must be considered in
         *  the caller). */
        if( rec_epoch != ssl->in_epoch )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "record from another epoch: "
                                        "expected %d, received %d",
                                        ssl->in_epoch, rec_epoch ) );

            /* Records from the next epoch are considered for buffering
             * (concretely: early Finished messages). */
            if( rec_epoch == (unsigned) ssl->in_epoch + 1 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "Consider record for buffering" ) );
                return( MBEDTLS_ERR_SSL_EARLY_MESSAGE );
            }

            return( MBEDTLS_ERR_SSL_UNEXPECTED_RECORD );
        }
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        /* For records from the correct epoch, check whether their
         * sequence number has been seen before. */
        else if( mbedtls_ssl_dtls_record_replay_check( (mbedtls_ssl_context *) ssl,
            &rec->ctr[0] ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "replayed record" ) );
            return( MBEDTLS_ERR_SSL_UNEXPECTED_RECORD );
        }
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    return( 0 );
}


#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
static int ssl_check_client_reconnect( mbedtls_ssl_context *ssl )
{
    unsigned int rec_epoch = ( ssl->in_ctr[0] << 8 ) | ssl->in_ctr[1];

    /*
     * Check for an epoch 0 ClientHello. We can't use in_msg here to
     * access the first byte of record content (handshake type), as we
     * have an active transform (possibly iv_len != 0), so use the
     * fact that the record header len is 13 instead.
     */
    if( rec_epoch == 0 &&
        ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
        ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER &&
        ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_left > 13 &&
        ssl->in_buf[13] == MBEDTLS_SSL_HS_CLIENT_HELLO )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "possible client reconnect "
                                    "from the same port" ) );
        return( ssl_handle_possible_reconnect( ssl ) );
    }

    return( 0 );
}
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE && MBEDTLS_SSL_SRV_C */

/*
 * If applicable, decrypt record content
 */
static int ssl_prepare_record_content( mbedtls_ssl_context *ssl,
                                       mbedtls_record *rec )
{
    int ret, done = 0;

    MBEDTLS_SSL_DEBUG_BUF( 4, "input record from network",
                           rec->buf, rec->buf_len );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_read != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_read()" ) );

        ret = mbedtls_ssl_hw_record_read( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_read", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */
    if( !done && ssl->transform_in != NULL )
    {
        unsigned char const old_msg_type = rec->type;

        if( ( ret = mbedtls_ssl_decrypt_buf( ssl, ssl->transform_in,
                                             rec ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_decrypt_buf", ret );

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            if( ret == MBEDTLS_ERR_SSL_UNEXPECTED_CID &&
                ssl->conf->ignore_unexpected_cid
                    == MBEDTLS_SSL_UNEXPECTED_CID_IGNORE )
            {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "ignoring unexpected CID" ) );
                ret = MBEDTLS_ERR_SSL_CONTINUE_PROCESSING;
            }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

            return( ret );
        }

        if( old_msg_type != rec->type )
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "record type after decrypt (before %d): %d",
                                        old_msg_type, rec->type ) );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "input payload after decrypt",
                               rec->buf + rec->data_offset, rec->data_len );

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        /* We have already checked the record content type
         * in ssl_parse_record_header(), failing or silently
         * dropping the record in the case of an unknown type.
         *
         * Since with the use of CIDs, the record content type
         * might change during decryption, re-check the record
         * content type, but treat a failure as fatal this time. */
        if( ssl_check_record_type( rec->type ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "unknown record type" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

        if( rec->data_len == 0 )
        {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3
                && rec->type != MBEDTLS_SSL_MSG_APPLICATION_DATA )
            {
                /* TLS v1.2 explicitly disallows zero-length messages which are not application data */
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid zero-length message type: %d", ssl->in_msgtype ) );
                return( MBEDTLS_ERR_SSL_INVALID_RECORD );
            }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

            ssl->nb_zero++;

            /*
             * Three or more empty messages may be a DoS attack
             * (excessive CPU consumption).
             */
            if( ssl->nb_zero > 3 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                            "messages, possible DoS attack" ) );
                /* Treat the records as if they were not properly authenticated,
                 * thereby failing the connection if we see more than allowed
                 * by the configured bad MAC threshold. */
                return( MBEDTLS_ERR_SSL_INVALID_MAC );
            }
        }
        else
            ssl->nb_zero = 0;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            ; /* in_ctr read from peer, not maintained internally */
        }
        else
#endif
        {
            unsigned i;
            for( i = 8; i > mbedtls_ssl_ep_len( ssl ); i-- )
                if( ++ssl->in_ctr[i - 1] != 0 )
                    break;

            /* The loop goes to its end iff the counter is wrapping */
            if( i == mbedtls_ssl_ep_len( ssl ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
                return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
            }
        }

    }

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        mbedtls_ssl_dtls_replay_update( ssl );
    }
#endif

    /* Check actual (decrypted) record content length against
     * configured maximum. */
    if( ssl->in_msglen > MBEDTLS_SSL_IN_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    return( 0 );
}

/*
 * Read a record.
 *
 * Silently ignore non-fatal alert (and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7) and continue reading until a valid record is found.
 *
 */

/* Helper functions for mbedtls_ssl_read_record(). */
static int ssl_consume_current_message( mbedtls_ssl_context *ssl );
static int ssl_get_next_record( mbedtls_ssl_context *ssl );
static int ssl_record_is_in_progress( mbedtls_ssl_context *ssl );

int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl,
                             unsigned update_hs_digest )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> read record" ) );

    if( ssl->keep_current_message == 0 )
    {
        do {

            ret = ssl_consume_current_message( ssl );
            if( ret != 0 )
                return( ret );

            if( ssl_record_is_in_progress( ssl ) == 0 )
            {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                int have_buffered = 0;

                /* We only check for buffered messages if the
                 * current datagram is fully consumed. */
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
                    ssl_next_record_is_in_datagram( ssl ) == 0 )
                {
                    if( ssl_load_buffered_message( ssl ) == 0 )
                        have_buffered = 1;
                }

                if( have_buffered == 0 )
#endif /* MBEDTLS_SSL_PROTO_DTLS */
                {
                    ret = ssl_get_next_record( ssl );
                    if( ret == MBEDTLS_ERR_SSL_CONTINUE_PROCESSING )
                        continue;

                    if( ret != 0 )
                    {
                        MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_get_next_record" ), ret );
                        return( ret );
                    }
                }
            }

            ret = mbedtls_ssl_handle_message_type( ssl );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
            if( ret == MBEDTLS_ERR_SSL_EARLY_MESSAGE )
            {
                /* Buffer future message */
                ret = ssl_buffer_message( ssl );
                if( ret != 0 )
                    return( ret );

                ret = MBEDTLS_ERR_SSL_CONTINUE_PROCESSING;
            }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        } while( MBEDTLS_ERR_SSL_NON_FATAL           == ret  ||
                 MBEDTLS_ERR_SSL_CONTINUE_PROCESSING == ret );

        if( 0 != ret )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ssl_handle_message_type" ), ret );
            return( ret );
        }

        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
            update_hs_digest == 1 )
        {
            mbedtls_ssl_update_handshake_status( ssl );
        }
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "reuse previously read message" ) );
        ssl->keep_current_message = 0;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read record" ) );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
static int ssl_next_record_is_in_datagram( mbedtls_ssl_context *ssl )
{
    if( ssl->in_left > ssl->next_record_offset )
        return( 1 );

    return( 0 );
}

static int ssl_load_buffered_message( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;
    mbedtls_ssl_hs_buffer * hs_buf;
    int ret = 0;

    if( hs == NULL )
        return( -1 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> ssl_load_buffered_messsage" ) );

    if( ssl->state == MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC ||
        ssl->state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC )
    {
        /* Check if we have seen a ChangeCipherSpec before.
         * If yes, synthesize a CCS record. */
        if( !hs->buffering.seen_ccs )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "CCS not seen in the current flight" ) );
            ret = -1;
            goto exit;
        }

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Injecting buffered CCS message" ) );
        ssl->in_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;
        ssl->in_msglen = 1;
        ssl->in_msg[0] = 1;

        /* As long as they are equal, the exact value doesn't matter. */
        ssl->in_left            = 0;
        ssl->next_record_offset = 0;

        hs->buffering.seen_ccs = 0;
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    /* Debug only */
    {
        unsigned offset;
        for( offset = 1; offset < MBEDTLS_SSL_MAX_BUFFERED_HS; offset++ )
        {
            hs_buf = &hs->buffering.hs[offset];
            if( hs_buf->is_valid == 1 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "Future message with sequence number %u %s buffered.",
                            hs->in_msg_seq + offset,
                            hs_buf->is_complete ? "fully" : "partially" ) );
            }
        }
    }
#endif /* MBEDTLS_DEBUG_C */

    /* Check if we have buffered and/or fully reassembled the
     * next handshake message. */
    hs_buf = &hs->buffering.hs[0];
    if( ( hs_buf->is_valid == 1 ) && ( hs_buf->is_complete == 1 ) )
    {
        /* Synthesize a record containing the buffered HS message. */
        size_t msg_len = ( hs_buf->data[1] << 16 ) |
                         ( hs_buf->data[2] << 8  ) |
                           hs_buf->data[3];

        /* Double-check that we haven't accidentally buffered
         * a message that doesn't fit into the input buffer. */
        if( msg_len + 12 > MBEDTLS_SSL_IN_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Next handshake message has been buffered - load" ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Buffered handshake message (incl. header)",
                               hs_buf->data, msg_len + 12 );

        ssl->in_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->in_hslen   = msg_len + 12;
        ssl->in_msglen  = msg_len + 12;
        memcpy( ssl->in_msg, hs_buf->data, ssl->in_hslen );

        ret = 0;
        goto exit;
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Next handshake message %u not or only partially bufffered",
                                    hs->in_msg_seq ) );
    }

    ret = -1;

exit:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= ssl_load_buffered_message" ) );
    return( ret );
}

static int ssl_buffer_make_space( mbedtls_ssl_context *ssl,
                                  size_t desired )
{
    int offset;
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "Attempt to free buffered messages to have %u bytes available",
                                (unsigned) desired ) );

    /* Get rid of future records epoch first, if such exist. */
    ssl_free_buffered_record( ssl );

    /* Check if we have enough space available now. */
    if( desired <= ( MBEDTLS_SSL_DTLS_MAX_BUFFERING -
                     hs->buffering.total_bytes_buffered ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Enough space available after freeing future epoch record" ) );
        return( 0 );
    }

    /* We don't have enough space to buffer the next expected handshake
     * message. Remove buffers used for future messages to gain space,
     * starting with the most distant one. */
    for( offset = MBEDTLS_SSL_MAX_BUFFERED_HS - 1;
         offset >= 0; offset-- )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Free buffering slot %d to make space for reassembly of next handshake message",
                                    offset ) );

        ssl_buffering_free_slot( ssl, (uint8_t) offset );

        /* Check if we have enough space available now. */
        if( desired <= ( MBEDTLS_SSL_DTLS_MAX_BUFFERING -
                         hs->buffering.total_bytes_buffered ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "Enough space available after freeing buffered HS messages" ) );
            return( 0 );
        }
    }

    return( -1 );
}

static int ssl_buffer_message( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;

    if( hs == NULL )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> ssl_buffer_message" ) );

    switch( ssl->in_msgtype )
    {
        case MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "Remember CCS message" ) );

            hs->buffering.seen_ccs = 1;
            break;

        case MBEDTLS_SSL_MSG_HANDSHAKE:
        {
            unsigned recv_msg_seq_offset;
            unsigned recv_msg_seq = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];
            mbedtls_ssl_hs_buffer *hs_buf;
            size_t msg_len = ssl->in_hslen - 12;

            /* We should never receive an old handshake
             * message - double-check nonetheless. */
            if( recv_msg_seq < ssl->handshake->in_msg_seq )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            recv_msg_seq_offset = recv_msg_seq - ssl->handshake->in_msg_seq;
            if( recv_msg_seq_offset >= MBEDTLS_SSL_MAX_BUFFERED_HS )
            {
                /* Silently ignore -- message too far in the future */
                MBEDTLS_SSL_DEBUG_MSG( 2,
                 ( "Ignore future HS message with sequence number %u, "
                   "buffering window %u - %u",
                   recv_msg_seq, ssl->handshake->in_msg_seq,
                   ssl->handshake->in_msg_seq + MBEDTLS_SSL_MAX_BUFFERED_HS - 1 ) );

                goto exit;
            }

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffering HS message with sequence number %u, offset %u ",
                                        recv_msg_seq, recv_msg_seq_offset ) );

            hs_buf = &hs->buffering.hs[ recv_msg_seq_offset ];

            /* Check if the buffering for this seq nr has already commenced. */
            if( !hs_buf->is_valid )
            {
                size_t reassembly_buf_sz;

                hs_buf->is_fragmented =
                    ( ssl_hs_is_proper_fragment( ssl ) == 1 );

                /* We copy the message back into the input buffer
                 * after reassembly, so check that it's not too large.
                 * This is an implementation-specific limitation
                 * and not one from the standard, hence it is not
                 * checked in ssl_check_hs_header(). */
                if( msg_len + 12 > MBEDTLS_SSL_IN_CONTENT_LEN )
                {
                    /* Ignore message */
                    goto exit;
                }

                /* Check if we have enough space to buffer the message. */
                if( hs->buffering.total_bytes_buffered >
                    MBEDTLS_SSL_DTLS_MAX_BUFFERING )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
                }

                reassembly_buf_sz = ssl_get_reassembly_buffer_size( msg_len,
                                                       hs_buf->is_fragmented );

                if( reassembly_buf_sz > ( MBEDTLS_SSL_DTLS_MAX_BUFFERING -
                                          hs->buffering.total_bytes_buffered ) )
                {
                    if( recv_msg_seq_offset > 0 )
                    {
                        /* If we can't buffer a future message because
                         * of space limitations -- ignore. */
                        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffering of future message of size %u would exceed the compile-time limit %u (already %u bytes buffered) -- ignore\n",
                             (unsigned) msg_len, MBEDTLS_SSL_DTLS_MAX_BUFFERING,
                             (unsigned) hs->buffering.total_bytes_buffered ) );
                        goto exit;
                    }
                    else
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffering of future message of size %u would exceed the compile-time limit %u (already %u bytes buffered) -- attempt to make space by freeing buffered future messages\n",
                             (unsigned) msg_len, MBEDTLS_SSL_DTLS_MAX_BUFFERING,
                             (unsigned) hs->buffering.total_bytes_buffered ) );
                    }

                    if( ssl_buffer_make_space( ssl, reassembly_buf_sz ) != 0 )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Reassembly of next message of size %u (%u with bitmap) would exceed the compile-time limit %u (already %u bytes buffered) -- fail\n",
                             (unsigned) msg_len,
                             (unsigned) reassembly_buf_sz,
                             MBEDTLS_SSL_DTLS_MAX_BUFFERING,
                             (unsigned) hs->buffering.total_bytes_buffered ) );
                        ret = MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
                        goto exit;
                    }
                }

                MBEDTLS_SSL_DEBUG_MSG( 2, ( "initialize reassembly, total length = %d",
                                            msg_len ) );

                hs_buf->data = mbedtls_calloc( 1, reassembly_buf_sz );
                if( hs_buf->data == NULL )
                {
                    ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
                    goto exit;
                }
                hs_buf->data_len = reassembly_buf_sz;

                /* Prepare final header: copy msg_type, length and message_seq,
                 * then add standardised fragment_offset and fragment_length */
                memcpy( hs_buf->data, ssl->in_msg, 6 );
                memset( hs_buf->data + 6, 0, 3 );
                memcpy( hs_buf->data + 9, hs_buf->data + 1, 3 );

                hs_buf->is_valid = 1;

                hs->buffering.total_bytes_buffered += reassembly_buf_sz;
            }
            else
            {
                /* Make sure msg_type and length are consistent */
                if( memcmp( hs_buf->data, ssl->in_msg, 4 ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Fragment header mismatch - ignore" ) );
                    /* Ignore */
                    goto exit;
                }
            }

            if( !hs_buf->is_complete )
            {
                size_t frag_len, frag_off;
                unsigned char * const msg = hs_buf->data + 12;

                /*
                 * Check and copy current fragment
                 */

                /* Validation of header fields already done in
                 * mbedtls_ssl_prepare_handshake_record(). */
                frag_off = ssl_get_hs_frag_off( ssl );
                frag_len = ssl_get_hs_frag_len( ssl );

                MBEDTLS_SSL_DEBUG_MSG( 2, ( "adding fragment, offset = %d, length = %d",
                                            frag_off, frag_len ) );
                memcpy( msg + frag_off, ssl->in_msg + 12, frag_len );

                if( hs_buf->is_fragmented )
                {
                    unsigned char * const bitmask = msg + msg_len;
                    ssl_bitmask_set( bitmask, frag_off, frag_len );
                    hs_buf->is_complete = ( ssl_bitmask_check( bitmask,
                                                               msg_len ) == 0 );
                }
                else
                {
                    hs_buf->is_complete = 1;
                }

                MBEDTLS_SSL_DEBUG_MSG( 2, ( "message %scomplete",
                                   hs_buf->is_complete ? "" : "not yet " ) );
            }

            break;
        }

        default:
            /* We don't buffer other types of messages. */
            break;
    }

exit:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= ssl_buffer_message" ) );
    return( ret );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

static int ssl_consume_current_message( mbedtls_ssl_context *ssl )
{
    /*
     * Consume last content-layer message and potentially
     * update in_msglen which keeps track of the contents'
     * consumption state.
     *
     * (1) Handshake messages:
     *     Remove last handshake message, move content
     *     and adapt in_msglen.
     *
     * (2) Alert messages:
     *     Consume whole record content, in_msglen = 0.
     *
     * (3) Change cipher spec:
     *     Consume whole record content, in_msglen = 0.
     *
     * (4) Application data:
     *     Don't do anything - the record layer provides
     *     the application data as a stream transport
     *     and consumes through mbedtls_ssl_read only.
     *
     */

    /* Case (1): Handshake messages */
    if( ssl->in_hslen != 0 )
    {
        /* Hard assertion to be sure that no application data
         * is in flight, as corrupting ssl->in_msglen during
         * ssl->in_offt != NULL is fatal. */
        if( ssl->in_offt != NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /*
         * Get next Handshake message in the current record
         */

        /* Notes:
         * (1) in_hslen is not necessarily the size of the
         *     current handshake content: If DTLS handshake
         *     fragmentation is used, that's the fragment
         *     size instead. Using the total handshake message
         *     size here is faulty and should be changed at
         *     some point.
         * (2) While it doesn't seem to cause problems, one
         *     has to be very careful not to assume that in_hslen
         *     is always <= in_msglen in a sensible communication.
         *     Again, it's wrong for DTLS handshake fragmentation.
         *     The following check is therefore mandatory, and
         *     should not be treated as a silently corrected assertion.
         *     Additionally, ssl->in_hslen might be arbitrarily out of
         *     bounds after handling a DTLS message with an unexpected
         *     sequence number, see mbedtls_ssl_prepare_handshake_record.
         */
        if( ssl->in_hslen < ssl->in_msglen )
        {
            ssl->in_msglen -= ssl->in_hslen;
            memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                     ssl->in_msglen );

            MBEDTLS_SSL_DEBUG_BUF( 4, "remaining content in record",
                                   ssl->in_msg, ssl->in_msglen );
        }
        else
        {
            ssl->in_msglen = 0;
        }

        ssl->in_hslen   = 0;
    }
    /* Case (4): Application data */
    else if( ssl->in_offt != NULL )
    {
        return( 0 );
    }
    /* Everything else (CCS & Alerts) */
    else
    {
        ssl->in_msglen = 0;
    }

    return( 0 );
}

static int ssl_record_is_in_progress( mbedtls_ssl_context *ssl )
{
    if( ssl->in_msglen > 0 )
        return( 1 );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)

static void ssl_free_buffered_record( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;
    if( hs == NULL )
        return;

    if( hs->buffering.future_record.data != NULL )
    {
        hs->buffering.total_bytes_buffered -=
            hs->buffering.future_record.len;

        mbedtls_free( hs->buffering.future_record.data );
        hs->buffering.future_record.data = NULL;
    }
}

static int ssl_load_buffered_record( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;
    unsigned char * rec;
    size_t rec_len;
    unsigned rec_epoch;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t in_buf_len = ssl->in_buf_len;
#else
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
#endif
    if( ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 0 );

    if( hs == NULL )
        return( 0 );

    rec       = hs->buffering.future_record.data;
    rec_len   = hs->buffering.future_record.len;
    rec_epoch = hs->buffering.future_record.epoch;

    if( rec == NULL )
        return( 0 );

    /* Only consider loading future records if the
     * input buffer is empty. */
    if( ssl_next_record_is_in_datagram( ssl ) == 1 )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> ssl_load_buffered_record" ) );

    if( rec_epoch != ssl->in_epoch )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffered record not from current epoch." ) );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "Found buffered record from current epoch - load" ) );

    /* Double-check that the record is not too large */
    if( rec_len > in_buf_len - (size_t)( ssl->in_hdr - ssl->in_buf ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    memcpy( ssl->in_hdr, rec, rec_len );
    ssl->in_left = rec_len;
    ssl->next_record_offset = 0;

    ssl_free_buffered_record( ssl );

exit:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= ssl_load_buffered_record" ) );
    return( 0 );
}

static int ssl_buffer_future_record( mbedtls_ssl_context *ssl,
                                     mbedtls_record const *rec )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;

    /* Don't buffer future records outside handshakes. */
    if( hs == NULL )
        return( 0 );

    /* Only buffer handshake records (we are only interested
     * in Finished messages). */
    if( rec->type != MBEDTLS_SSL_MSG_HANDSHAKE )
        return( 0 );

    /* Don't buffer more than one future epoch record. */
    if( hs->buffering.future_record.data != NULL )
        return( 0 );

    /* Don't buffer record if there's not enough buffering space remaining. */
    if( rec->buf_len > ( MBEDTLS_SSL_DTLS_MAX_BUFFERING -
                         hs->buffering.total_bytes_buffered ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffering of future epoch record of size %u would exceed the compile-time limit %u (already %u bytes buffered) -- ignore\n",
                        (unsigned) rec->buf_len, MBEDTLS_SSL_DTLS_MAX_BUFFERING,
                        (unsigned) hs->buffering.total_bytes_buffered ) );
        return( 0 );
    }

    /* Buffer record */
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "Buffer record from epoch %u",
                                ssl->in_epoch + 1 ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Buffered record", rec->buf, rec->buf_len );

    /* ssl_parse_record_header() only considers records
     * of the next epoch as candidates for buffering. */
    hs->buffering.future_record.epoch = ssl->in_epoch + 1;
    hs->buffering.future_record.len   = rec->buf_len;

    hs->buffering.future_record.data =
        mbedtls_calloc( 1, hs->buffering.future_record.len );
    if( hs->buffering.future_record.data == NULL )
    {
        /* If we run out of RAM trying to buffer a
         * record from the next epoch, just ignore. */
        return( 0 );
    }

    memcpy( hs->buffering.future_record.data, rec->buf, rec->buf_len );

    hs->buffering.total_bytes_buffered += rec->buf_len;
    return( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_DTLS */

static int ssl_get_next_record( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_record rec;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /* We might have buffered a future record; if so,
     * and if the epoch matches now, load it.
     * On success, this call will set ssl->in_left to
     * the length of the buffered record, so that
     * the calls to ssl_fetch_input() below will
     * essentially be no-ops. */
    ret = ssl_load_buffered_record( ssl );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /* Ensure that we have enough space available for the default form
     * of TLS / DTLS record headers (5 Bytes for TLS, 13 Bytes for DTLS,
     * with no space for CIDs counted in). */
    ret = mbedtls_ssl_fetch_input( ssl, mbedtls_ssl_in_hdr_len( ssl ) );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( ret );
    }

    ret = ssl_parse_record_header( ssl, ssl->in_hdr, ssl->in_left, &rec );
    if( ret != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            if( ret == MBEDTLS_ERR_SSL_EARLY_MESSAGE )
            {
                ret = ssl_buffer_future_record( ssl, &rec );
                if( ret != 0 )
                    return( ret );

                /* Fall through to handling of unexpected records */
                ret = MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
            }

            if( ret == MBEDTLS_ERR_SSL_UNEXPECTED_RECORD )
            {
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
                /* Reset in pointers to default state for TLS/DTLS records,
                 * assuming no CID and no offset between record content and
                 * record plaintext. */
                mbedtls_ssl_update_in_pointers( ssl );

                /* Setup internal message pointers from record structure. */
                ssl->in_msgtype = rec.type;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
                ssl->in_len = ssl->in_cid + rec.cid_len;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
                ssl->in_iv  = ssl->in_msg = ssl->in_len + 2;
                ssl->in_msglen = rec.data_len;

                ret = ssl_check_client_reconnect( ssl );
                MBEDTLS_SSL_DEBUG_RET( 2, "ssl_check_client_reconnect", ret );
                if( ret != 0 )
                    return( ret );
#endif

                /* Skip unexpected record (but not whole datagram) */
                ssl->next_record_offset = rec.buf_len;

                MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding unexpected record "
                                            "(header)" ) );
            }
            else
            {
                /* Skip invalid record and the rest of the datagram */
                ssl->next_record_offset = 0;
                ssl->in_left = 0;

                MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record "
                                            "(header)" ) );
            }

            /* Get next record */
            return( MBEDTLS_ERR_SSL_CONTINUE_PROCESSING );
        }
        else
#endif
        {
            return( ret );
        }
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Remember offset of next record within datagram. */
        ssl->next_record_offset = rec.buf_len;
        if( ssl->next_record_offset < ssl->in_left )
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "more than one record within datagram" ) );
        }
    }
    else
#endif
    {
        /*
         * Fetch record contents from underlying transport.
         */
        ret = mbedtls_ssl_fetch_input( ssl, rec.buf_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
            return( ret );
        }

        ssl->in_left = 0;
    }

    /*
     * Decrypt record contents.
     */

    if( ( ret = ssl_prepare_record_content( ssl, &rec ) ) != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Silently discard invalid records */
            if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                /* Except when waiting for Finished as a bad mac here
                 * probably means something went wrong in the handshake
                 * (eg wrong psk used, mitm downgrade attempt, etc.) */
                if( ssl->state == MBEDTLS_SSL_CLIENT_FINISHED ||
                    ssl->state == MBEDTLS_SSL_SERVER_FINISHED )
                {
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
                    if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
                    {
                        mbedtls_ssl_send_alert_message( ssl,
                                MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
                    }
#endif
                    return( ret );
                }

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
                if( ssl->conf->badmac_limit != 0 &&
                    ++ssl->badmac_seen >= ssl->conf->badmac_limit )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "too many records with bad MAC" ) );
                    return( MBEDTLS_ERR_SSL_INVALID_MAC );
                }
#endif

                /* As above, invalid records cause
                 * dismissal of the whole datagram. */

                ssl->next_record_offset = 0;
                ssl->in_left = 0;

                MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record (mac)" ) );
                return( MBEDTLS_ERR_SSL_CONTINUE_PROCESSING );
            }

            return( ret );
        }
        else
#endif
        {
            /* Error out (and send alert) on invalid records */
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
            if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                        MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
            }
#endif
            return( ret );
        }
    }


    /* Reset in pointers to default state for TLS/DTLS records,
     * assuming no CID and no offset between record content and
     * record plaintext. */
    mbedtls_ssl_update_in_pointers( ssl );
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    ssl->in_len = ssl->in_cid + rec.cid_len;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    ssl->in_iv  = ssl->in_len + 2;

    /* The record content type may change during decryption,
     * so re-read it. */
    ssl->in_msgtype = rec.type;
    /* Also update the input buffer, because unfortunately
     * the server-side ssl_parse_client_hello() reparses the
     * record header when receiving a ClientHello initiating
     * a renegotiation. */
    ssl->in_hdr[0] = rec.type;
    ssl->in_msg    = rec.buf + rec.data_offset;
    ssl->in_msglen = rec.data_len;
    ssl->in_len[0] = (unsigned char)( rec.data_len >> 8 );
    ssl->in_len[1] = (unsigned char)( rec.data_len      );

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->transform_in != NULL &&
        ssl->session_in->compression == MBEDTLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_decompress_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_decompress_buf", ret );
            return( ret );
        }

        /* Check actual (decompress) record content length against
         * configured maximum. */
        if( ssl->in_msglen > MBEDTLS_SSL_IN_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }
#endif /* MBEDTLS_ZLIB_SUPPORT */

    return( 0 );
}

int mbedtls_ssl_handle_message_type( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Handle particular types of records
     */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        if( ( ret = mbedtls_ssl_prepare_handshake_record( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        if( ssl->in_msglen != 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid CCS message, len: %d",
                           ssl->in_msglen ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->in_msg[0] != 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid CCS message, content: %02x",
                                        ssl->in_msg[0] ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            ssl->state != MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC    &&
            ssl->state != MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC )
        {
            if( ssl->handshake == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "dropping ChangeCipherSpec outside handshake" ) );
                return( MBEDTLS_ERR_SSL_UNEXPECTED_RECORD );
            }

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received out-of-order ChangeCipherSpec - remember" ) );
            return( MBEDTLS_ERR_SSL_EARLY_MESSAGE );
        }
#endif
    }

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
    {
        if( ssl->in_msglen != 2 )
        {
            /* Note: Standard allows for more than one 2 byte alert
               to be packed in a single message, but Mbed TLS doesn't
               currently support this. */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid alert message, len: %d",
                           ssl->in_msglen ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "got an alert message, type: [%d:%d]",
                       ssl->in_msg[0], ssl->in_msg[1] ) );

        /*
         * Ignore non-fatal alerts, except close_notify and no_renegotiation
         */
        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_FATAL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "is a fatal alert message (msg %d)",
                           ssl->in_msg[1] ) );
            return( MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE );
        }

        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a close notify message" ) );
            return( MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY );
        }

#if defined(MBEDTLS_SSL_RENEGOTIATION_ENABLED)
        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no renegotiation alert" ) );
            /* Will be handled when trying to parse ServerHello */
            return( 0 );
        }
#endif

#if defined(MBEDTLS_SSL_PROTO_SSL3) && defined(MBEDTLS_SSL_SRV_C)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 &&
            ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
            ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_NO_CERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no_cert" ) );
            /* Will be handled in mbedtls_ssl_parse_certificate() */
            return( 0 );
        }
#endif /* MBEDTLS_SSL_PROTO_SSL3 && MBEDTLS_SSL_SRV_C */

        /* Silently ignore: fetch new message */
        return MBEDTLS_ERR_SSL_NON_FATAL;
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Drop unexpected ApplicationData records,
         * except at the beginning of renegotiations */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA &&
            ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            && ! ( ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS &&
                   ssl->state == MBEDTLS_SSL_SERVER_HELLO )
#endif
            )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "dropping unexpected ApplicationData" ) );
            return( MBEDTLS_ERR_SSL_NON_FATAL );
        }

        if( ssl->handshake != NULL &&
            ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER  )
        {
            mbedtls_ssl_handshake_wrapup_free_hs_transform( ssl );
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    return( 0 );
}

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl )
{
    return( mbedtls_ssl_send_alert_message( ssl,
                  MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                  MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE ) );
}

int mbedtls_ssl_send_alert_message( mbedtls_ssl_context *ssl,
                            unsigned char level,
                            unsigned char message )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> send alert message" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "send alert level=%u message=%u", level, message ));

    ssl->out_msgtype = MBEDTLS_SSL_MSG_ALERT;
    ssl->out_msglen = 2;
    ssl->out_msg[0] = level;
    ssl->out_msg[1] = message;

    if( ( ret = mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= send alert message" ) );

    return( 0 );
}

int mbedtls_ssl_write_change_cipher_spec( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;
    ssl->out_msglen  = 1;
    ssl->out_msg[0]  = 1;

    ssl->state++;

    if( ( ret = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );

    return( 0 );
}

int mbedtls_ssl_parse_change_cipher_spec( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse change cipher spec" ) );

    if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad change cipher spec message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /* CCS records are only accepted if they have length 1 and content '1',
     * so we don't need to check this here. */

    /*
     * Switch to our negotiated transform and session parameters for inbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for inbound data" ) );
    ssl->transform_in = ssl->transform_negotiate;
    ssl->session_in = ssl->session_negotiate;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        mbedtls_ssl_dtls_replay_reset( ssl );
#endif

        /* Increment epoch */
        if( ++ssl->in_epoch == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "DTLS epoch would wrap" ) );
            /* This is highly unlikely to happen for legitimate reasons, so
               treat it as an attack and don't send an alert. */
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    memset( ssl->in_ctr, 0, 8 );

    mbedtls_ssl_update_in_pointers( ssl );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_INBOUND ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                            MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

    ssl->state++;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse change cipher spec" ) );

    return( 0 );
}

/* Once ssl->out_hdr as the address of the beginning of the
 * next outgoing record is set, deduce the other pointers.
 *
 * Note: For TLS, we save the implicit record sequence number
 *       (entering MAC computation) in the 8 bytes before ssl->out_hdr,
 *       and the caller has to make sure there's space for this.
 */

void mbedtls_ssl_update_out_pointers( mbedtls_ssl_context *ssl,
                                      mbedtls_ssl_transform *transform )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_ctr = ssl->out_hdr +  3;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        ssl->out_cid = ssl->out_ctr +  8;
        ssl->out_len = ssl->out_cid;
        if( transform != NULL )
            ssl->out_len += transform->out_cid_len;
#else /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
        ssl->out_len = ssl->out_ctr + 8;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
        ssl->out_iv  = ssl->out_len + 2;
    }
    else
#endif
    {
        ssl->out_ctr = ssl->out_hdr - 8;
        ssl->out_len = ssl->out_hdr + 3;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        ssl->out_cid = ssl->out_len;
#endif
        ssl->out_iv  = ssl->out_hdr + 5;
    }

    /* Adjust out_msg to make space for explicit IV, if used. */
    if( transform != NULL &&
        ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
    {
        ssl->out_msg = ssl->out_iv + transform->ivlen - transform->fixed_ivlen;
    }
    else
        ssl->out_msg = ssl->out_iv;
}

/* Once ssl->in_hdr as the address of the beginning of the
 * next incoming record is set, deduce the other pointers.
 *
 * Note: For TLS, we save the implicit record sequence number
 *       (entering MAC computation) in the 8 bytes before ssl->in_hdr,
 *       and the caller has to make sure there's space for this.
 */

void mbedtls_ssl_update_in_pointers( mbedtls_ssl_context *ssl )
{
    /* This function sets the pointers to match the case
     * of unprotected TLS/DTLS records, with both  ssl->in_iv
     * and ssl->in_msg pointing to the beginning of the record
     * content.
     *
     * When decrypting a protected record, ssl->in_msg
     * will be shifted to point to the beginning of the
     * record plaintext.
     */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* This sets the header pointers to match records
         * without CID. When we receive a record containing
         * a CID, the fields are shifted accordingly in
         * ssl_parse_record_header(). */
        ssl->in_ctr = ssl->in_hdr +  3;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        ssl->in_cid = ssl->in_ctr +  8;
        ssl->in_len = ssl->in_cid; /* Default: no CID */
#else /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
        ssl->in_len = ssl->in_ctr + 8;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
        ssl->in_iv  = ssl->in_len + 2;
    }
    else
#endif
    {
        ssl->in_ctr = ssl->in_hdr - 8;
        ssl->in_len = ssl->in_hdr + 3;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        ssl->in_cid = ssl->in_len;
#endif
        ssl->in_iv  = ssl->in_hdr + 5;
    }

    /* This will be adjusted at record decryption time. */
    ssl->in_msg = ssl->in_iv;
}

/*
 * Setup an SSL context
 */

void mbedtls_ssl_reset_in_out_pointers( mbedtls_ssl_context *ssl )
{
    /* Set the incoming and outgoing record pointers. */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_hdr = ssl->out_buf;
        ssl->in_hdr  = ssl->in_buf;
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        ssl->out_hdr = ssl->out_buf + 8;
        ssl->in_hdr  = ssl->in_buf  + 8;
    }

    /* Derive other internal pointers. */
    mbedtls_ssl_update_out_pointers( ssl, NULL /* no transform enabled */ );
    mbedtls_ssl_update_in_pointers ( ssl );
}

/*
 * SSL get accessors
 */
size_t mbedtls_ssl_get_bytes_avail( const mbedtls_ssl_context *ssl )
{
    return( ssl->in_offt == NULL ? 0 : ssl->in_msglen );
}

int mbedtls_ssl_check_pending( const mbedtls_ssl_context *ssl )
{
    /*
     * Case A: We're currently holding back
     * a message for further processing.
     */

    if( ssl->keep_current_message == 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: record held back for processing" ) );
        return( 1 );
    }

    /*
     * Case B: Further records are pending in the current datagram.
     */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->in_left > ssl->next_record_offset )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: more records within current datagram" ) );
        return( 1 );
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /*
     * Case C: A handshake message is being processed.
     */

    if( ssl->in_hslen > 0 && ssl->in_hslen < ssl->in_msglen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: more handshake messages within current record" ) );
        return( 1 );
    }

    /*
     * Case D: An application data message is being processed
     */
    if( ssl->in_offt != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: application data record is being processed" ) );
        return( 1 );
    }

    /*
     * In all other cases, the rest of the message can be dropped.
     * As in ssl_get_next_record, this needs to be adapted if
     * we implement support for multiple alerts in single records.
     */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: nothing pending" ) );
    return( 0 );
}


int mbedtls_ssl_get_record_expansion( const mbedtls_ssl_context *ssl )
{
    size_t transform_expansion = 0;
    const mbedtls_ssl_transform *transform = ssl->transform_out;
    unsigned block_size;

    size_t out_hdr_len = mbedtls_ssl_out_hdr_len( ssl );

    if( transform == NULL )
        return( (int) out_hdr_len );

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->session_out->compression != MBEDTLS_SSL_COMPRESS_NULL )
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
#endif

    switch( mbedtls_cipher_get_cipher_mode( &transform->cipher_ctx_enc ) )
    {
        case MBEDTLS_MODE_GCM:
        case MBEDTLS_MODE_CCM:
        case MBEDTLS_MODE_CHACHAPOLY:
        case MBEDTLS_MODE_STREAM:
            transform_expansion = transform->minlen;
            break;

        case MBEDTLS_MODE_CBC:

            block_size = mbedtls_cipher_get_block_size(
                &transform->cipher_ctx_enc );

            /* Expansion due to the addition of the MAC. */
            transform_expansion += transform->maclen;

            /* Expansion due to the addition of CBC padding;
             * Theoretically up to 256 bytes, but we never use
             * more than the block size of the underlying cipher. */
            transform_expansion += block_size;

            /* For TLS 1.1 or higher, an explicit IV is added
             * after the record header. */
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
                transform_expansion += block_size;
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 */

            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if( transform->out_cid_len != 0 )
        transform_expansion += MBEDTLS_SSL_MAX_CID_EXPANSION;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    return( (int)( out_hdr_len + transform_expansion ) );
}

#if defined(MBEDTLS_SSL_RENEGOTIATION)
/*
 * Check record counters and renegotiate if they're above the limit.
 */
static int ssl_check_ctr_renegotiate( mbedtls_ssl_context *ssl )
{
    size_t ep_len = mbedtls_ssl_ep_len( ssl );
    int in_ctr_cmp;
    int out_ctr_cmp;

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER ||
        ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING ||
        ssl->conf->disable_renegotiation == MBEDTLS_SSL_RENEGOTIATION_DISABLED )
    {
        return( 0 );
    }

    in_ctr_cmp = memcmp( ssl->in_ctr + ep_len,
                        ssl->conf->renego_period + ep_len, 8 - ep_len );
    out_ctr_cmp = memcmp( ssl->cur_out_ctr + ep_len,
                          ssl->conf->renego_period + ep_len, 8 - ep_len );

    if( in_ctr_cmp <= 0 && out_ctr_cmp <= 0 )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "record counter limit reached: renegotiate" ) );
    return( mbedtls_ssl_renegotiate( ssl ) );
}
#endif /* MBEDTLS_SSL_RENEGOTIATION */

/*
 * Receive application data decrypted from the SSL layer
 */
int mbedtls_ssl_read( mbedtls_ssl_context *ssl, unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> read" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
            return( ret );

        if( ssl->handshake != NULL &&
            ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
        {
            if( ( ret = mbedtls_ssl_flight_transmit( ssl ) ) != 0 )
                return( ret );
        }
    }
#endif

    /*
     * Check if renegotiation is necessary and/or handshake is
     * in process. If yes, perform/continue, and fall through
     * if an unexpected packet is received while the client
     * is waiting for the ServerHello.
     *
     * (There is no equivalent to the last condition on
     *  the server-side as it is not treated as within
     *  a handshake while waiting for the ClientHello
     *  after a renegotiation request.)
     */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ret = ssl_check_ctr_renegotiate( ssl );
    if( ret != MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
        ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        ret = mbedtls_ssl_handshake( ssl );
        if( ret != MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
            ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
            return( ret );
        }
    }

    /* Loop as long as no application data record is available */
    while( ssl->in_offt == NULL )
    {
        /* Start timer if not already running */
        if( ssl->f_get_timer != NULL &&
            ssl->f_get_timer( ssl->p_timer ) == -1 )
        {
            mbedtls_ssl_set_timer( ssl, ssl->conf->read_timeout );
        }

        if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
        {
            if( ret == MBEDTLS_ERR_SSL_CONN_EOF )
                return( 0 );

            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
            return( ret );
        }

        if( ssl->in_msglen  == 0 &&
            ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            /*
             * OpenSSL sends empty messages to randomize the IV
             */
            if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
            {
                if( ret == MBEDTLS_ERR_SSL_CONN_EOF )
                    return( 0 );

                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
                return( ret );
            }
        }

        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received handshake message" ) );

            /*
             * - For client-side, expect SERVER_HELLO_REQUEST.
             * - For server-side, expect CLIENT_HELLO.
             * - Fail (TLS) or silently drop record (DTLS) in other cases.
             */

#if defined(MBEDTLS_SSL_CLI_C)
            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
                ( ssl->in_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST ||
                  ssl->in_hslen  != mbedtls_ssl_hs_hdr_len( ssl ) ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake received (not HelloRequest)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
                {
                    continue;
                }
#endif
                return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                ssl->in_msg[0] != MBEDTLS_SSL_HS_CLIENT_HELLO )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake received (not ClientHello)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
                {
                    continue;
                }
#endif
                return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
            /* Determine whether renegotiation attempt should be accepted */
            if( ! ( ssl->conf->disable_renegotiation == MBEDTLS_SSL_RENEGOTIATION_DISABLED ||
                    ( ssl->secure_renegotiation == MBEDTLS_SSL_LEGACY_RENEGOTIATION &&
                      ssl->conf->allow_legacy_renegotiation ==
                                                   MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION ) ) )
            {
                /*
                 * Accept renegotiation request
                 */

                /* DTLS clients need to know renego is server-initiated */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
                    ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
                {
                    ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_PENDING;
                }
#endif
                ret = mbedtls_ssl_start_renegotiation( ssl );
                if( ret != MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
                    ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_start_renegotiation",
                                           ret );
                    return( ret );
                }
            }
            else
#endif /* MBEDTLS_SSL_RENEGOTIATION */
            {
                /*
                 * Refuse renegotiation
                 */

                MBEDTLS_SSL_DEBUG_MSG( 3, ( "refusing renegotiation, sending alert" ) );

#if defined(MBEDTLS_SSL_PROTO_SSL3)
                if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
                {
                    /* SSLv3 does not have a "no_renegotiation" warning, so
                       we send a fatal alert and abort the connection. */
                    mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                    MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
                    return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }
                else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
                if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
                {
                    if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                    MBEDTLS_SSL_ALERT_LEVEL_WARNING,
                                    MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION ) ) != 0 )
                    {
                        return( ret );
                    }
                }
                else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 ||
          MBEDTLS_SSL_PROTO_TLS1_2 */
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
                }
            }

            /* At this point, we don't know whether the renegotiation has been
             * completed or not. The cases to consider are the following:
             * 1) The renegotiation is complete. In this case, no new record
             *    has been read yet.
             * 2) The renegotiation is incomplete because the client received
             *    an application data record while awaiting the ServerHello.
             * 3) The renegotiation is incomplete because the client received
             *    a non-handshake, non-application data message while awaiting
             *    the ServerHello.
             * In each of these case, looping will be the proper action:
             * - For 1), the next iteration will read a new record and check
             *   if it's application data.
             * - For 2), the loop condition isn't satisfied as application data
             *   is present, hence continue is the same as break
             * - For 3), the loop condition is satisfied and read_record
             *   will re-deliver the message that was held back by the client
             *   when expecting the ServerHello.
             */
            continue;
        }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        else if( ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
        {
            if( ssl->conf->renego_max_records >= 0 )
            {
                if( ++ssl->renego_records_seen > ssl->conf->renego_max_records )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "renegotiation requested, "
                                        "but not honored by client" ) );
                    return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }
            }
        }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

        /* Fatal and closure alerts handled by mbedtls_ssl_read_record() */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ignoring non-fatal non-closure alert" ) );
            return( MBEDTLS_ERR_SSL_WANT_READ );
        }

        if( ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad application data message" ) );
            return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->in_offt = ssl->in_msg;

        /* We're going to return something now, cancel timer,
         * except if handshake (renegotiation) is in progress */
        if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
            mbedtls_ssl_set_timer( ssl, 0 );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* If we requested renego but received AppData, resend HelloRequest.
         * Do it now, after setting in_offt, to avoid taking this branch
         * again if ssl_write_hello_request() returns WANT_WRITE */
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
            ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
        {
            if( ( ret = mbedtls_ssl_resend_hello_request( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend_hello_request",
                                       ret );
                return( ret );
            }
        }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    memcpy( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
    {
        /* all bytes consumed */
        ssl->in_offt = NULL;
        ssl->keep_current_message = 0;
    }
    else
    {
        /* more data available */
        ssl->in_offt += n;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );

    return( (int) n );
}

/*
 * Send application data to be encrypted by the SSL layer, taking care of max
 * fragment length and buffer size.
 *
 * According to RFC 5246 Section 6.2.1:
 *
 *      Zero-length fragments of Application data MAY be sent as they are
 *      potentially useful as a traffic analysis countermeasure.
 *
 * Therefore, it is possible that the input message length is 0 and the
 * corresponding return code is 0 on success.
 */
static int ssl_write_real( mbedtls_ssl_context *ssl,
                           const unsigned char *buf, size_t len )
{
    int ret = mbedtls_ssl_get_max_out_record_payload( ssl );
    const size_t max_len = (size_t) ret;

    if( ret < 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_max_out_record_payload", ret );
        return( ret );
    }

    if( len > max_len )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "fragment larger than the (negotiated) "
                                "maximum fragment length: %d > %d",
                                len, max_len ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }
        else
#endif
            len = max_len;
    }

    if( ssl->out_left != 0 )
    {
        /*
         * The user has previously tried to send the data and
         * MBEDTLS_ERR_SSL_WANT_WRITE or the message was only partially
         * written. In this case, we expect the high-level write function
         * (e.g. mbedtls_ssl_write()) to be called with the same parameters
         */
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
            return( ret );
        }
    }
    else
    {
        /*
         * The user is trying to send a message the first time, so we need to
         * copy the data into the internal buffers and setup the data structure
         * to keep track of partial writes
         */
        ssl->out_msglen  = len;
        ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, len );

        if( ( ret = mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
            return( ret );
        }
    }

    return( (int) len );
}

/*
 * Write application data, doing 1/n-1 splitting if necessary.
 *
 * With non-blocking I/O, ssl_write_real() may return WANT_WRITE,
 * then the caller will call us again with the same arguments, so
 * remember whether we already did the split or not.
 */
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
static int ssl_write_split( mbedtls_ssl_context *ssl,
                            const unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ssl->conf->cbc_record_splitting ==
            MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED ||
        len <= 1 ||
        ssl->minor_ver > MBEDTLS_SSL_MINOR_VERSION_1 ||
        mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc )
                                != MBEDTLS_MODE_CBC )
    {
        return( ssl_write_real( ssl, buf, len ) );
    }

    if( ssl->split_done == 0 )
    {
        if( ( ret = ssl_write_real( ssl, buf, 1 ) ) <= 0 )
            return( ret );
        ssl->split_done = 1;
    }

    if( ( ret = ssl_write_real( ssl, buf + 1, len - 1 ) ) <= 0 )
        return( ret );
    ssl->split_done = 0;

    return( ret + 1 );
}
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

/*
 * Write application data (public-facing wrapper)
 */
int mbedtls_ssl_write( mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write" ) );

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ( ret = ssl_check_ctr_renegotiate( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
            return( ret );
        }
    }

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    ret = ssl_write_split( ssl, buf, len );
#else
    ret = ssl_write_real( ssl, buf, len );
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write" ) );

    return( ret );
}

/*
 * Notify the peer that the connection is being closed
 */
int mbedtls_ssl_close_notify( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write close notify" ) );

    if( ssl->out_left != 0 )
        return( mbedtls_ssl_flush_output( ssl ) );

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_WARNING,
                        MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_send_alert_message", ret );
            return( ret );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write close notify" ) );

    return( 0 );
}

void mbedtls_ssl_transform_free( mbedtls_ssl_transform *transform )
{
    if( transform == NULL )
        return;

#if defined(MBEDTLS_ZLIB_SUPPORT)
    deflateEnd( &transform->ctx_deflate );
    inflateEnd( &transform->ctx_inflate );
#endif

    mbedtls_cipher_free( &transform->cipher_ctx_enc );
    mbedtls_cipher_free( &transform->cipher_ctx_dec );

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    mbedtls_md_free( &transform->md_ctx_enc );
    mbedtls_md_free( &transform->md_ctx_dec );
#endif

    mbedtls_platform_zeroize( transform, sizeof( mbedtls_ssl_transform ) );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)

void mbedtls_ssl_buffering_free( mbedtls_ssl_context *ssl )
{
    unsigned offset;
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;

    if( hs == NULL )
        return;

    ssl_free_buffered_record( ssl );

    for( offset = 0; offset < MBEDTLS_SSL_MAX_BUFFERED_HS; offset++ )
        ssl_buffering_free_slot( ssl, offset );
}

static void ssl_buffering_free_slot( mbedtls_ssl_context *ssl,
                                     uint8_t slot )
{
    mbedtls_ssl_handshake_params * const hs = ssl->handshake;
    mbedtls_ssl_hs_buffer * const hs_buf = &hs->buffering.hs[slot];

    if( slot >= MBEDTLS_SSL_MAX_BUFFERED_HS )
        return;

    if( hs_buf->is_valid == 1 )
    {
        hs->buffering.total_bytes_buffered -= hs_buf->data_len;
        mbedtls_platform_zeroize( hs_buf->data, hs_buf->data_len );
        mbedtls_free( hs_buf->data );
        memset( hs_buf, 0, sizeof( mbedtls_ssl_hs_buffer ) );
    }
}

#endif /* MBEDTLS_SSL_PROTO_DTLS */

/*
 * Convert version numbers to/from wire format
 * and, for DTLS, to/from TLS equivalent.
 *
 * For TLS this is the identity.
 * For DTLS, use 1's complement (v -> 255 - v, and then map as follows:
 * 1.0 <-> 3.2      (DTLS 1.0 is based on TLS 1.1)
 * 1.x <-> 3.x+1    for x != 0 (DTLS 1.2 based on TLS 1.2)
 */
void mbedtls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( minor == MBEDTLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
    else
#else
    ((void) transport);
#endif
    {
        ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
    }
}

void mbedtls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == MBEDTLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
    else
#else
    ((void) transport);
#endif
    {
        *major = ver[0];
        *minor = ver[1];
    }
}

#endif /* MBEDTLS_SSL_TLS_C */
