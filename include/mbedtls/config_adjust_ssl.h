/**
 * \file mbedtls/config_adjust_ssl.h
 * \brief Adjust TLS configuration
 *
 * This is an internal header. Do not include it directly.
 *
 * Automatically enable certain dependencies. Generally, MBEDTLS_xxx
 * configurations need to be explicitly enabled by the user: enabling
 * MBEDTLS_xxx_A but not MBEDTLS_xxx_B when A requires B results in a
 * compilation error. However, we do automatically enable certain options
 * in some circumstances. One case is if MBEDTLS_xxx_B is an internal option
 * used to identify parts of a module that are used by other module, and we
 * don't want to make the symbol MBEDTLS_xxx_B part of the public API.
 * Another case is if A didn't depend on B in earlier versions, and we
 * want to use B in A but we need to preserve backward compatibility with
 * configurations that explicitly activate MBEDTLS_xxx_A but not
 * MBEDTLS_xxx_B.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONFIG_ADJUST_SSL_H
#define MBEDTLS_CONFIG_ADJUST_SSL_H

#if !defined(MBEDTLS_CONFIG_FILES_READ)
#error "Do not include mbedtls/config_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/* The following blocks make it easier to disable all of TLS,
 * or of TLS 1.2 or 1.3 or DTLS, without having to manually disable all
 * key exchanges, options and extensions related to them. */

#if !defined(MBEDTLS_SSL_TLS_C)
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_PROTO_DTLS
#endif

#if !(defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_SESSION_TICKETS))
#undef MBEDTLS_SSL_TICKET_C
#endif

#if !defined(MBEDTLS_SSL_PROTO_DTLS)
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_SRTP
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_EARLY_DATA
#undef MBEDTLS_SSL_RECORD_SIZE_LIMIT
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED))
#define MBEDTLS_SSL_TLS1_2_SOME_ECC
#endif

/* Key exchanges using a certificate */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)           || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)   || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)      || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED
#endif

/* Key exchanges in either TLS 1.2 or 1.3 which are using an ECDSA
 * signature */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_WITH_ECDSA_ANY_ENABLED
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#define MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED
#endif

/* Key exchanges allowing client certificate requests.
 *
 * Note: that's almost the same as MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED
 * above, except RSA-PSK uses a server certificate but no client cert.
 *
 * Note: this difference is specific to TLS 1.2, as with TLS 1.3, things are
 * more symmetrical: client certs and server certs are either both allowed
 * (Ephemeral mode) or both disallowed (PSK and PKS-Ephemeral modes).
 */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)           ||       \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)       ||       \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)     ||       \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)   ||       \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)    ||       \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED
#endif

/* Helper to state that certificate-based client authentication through ECDSA
 * is supported in TLS 1.2 */
#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED) && \
    defined(MBEDTLS_PK_CAN_ECDSA_SIGN) && defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
#define MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED
#endif

/* ECDSA required for certificates in either TLS 1.2 or 1.3 */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED
#endif

/* Key exchanges involving server signature in ServerKeyExchange */
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED
#endif

/* Key exchanges using ECDH */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)      || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED
#endif

/* Key exchanges that don't involve ephemeral keys */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)           || \
    defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)           || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED
#endif

/* Key exchanges that involve ephemeral keys */
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)   || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED
#endif

/* Key exchanges using a PSK */
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)           || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED
#endif

/* Key exchanges using DHE */
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)       || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED
#endif

/* Key exchanges using ECDHE */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)   || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED
#endif

/* TLS 1.2 key exchanges using ECDH or ECDHE*/
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED
#endif

/* TLS 1.3 PSK key exchanges */
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED
#endif

/* TLS 1.2 or 1.3 key exchanges with PSK */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
#define MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED
#endif

/* TLS 1.3 ephemeral key exchanges */
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED
#endif

/* TLS 1.3 key exchanges using ECDHE */
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED) && \
    defined(PSA_WANT_ALG_ECDH)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_ECDHE_ENABLED
#endif

/* TLS 1.2 or 1.3 key exchanges using ECDH or ECDHE */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_ECDHE_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED
#endif

/* TLS 1.2 XXDH key exchanges: ECDH or ECDHE or FFDH */
#if (defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED))
#define MBEDTLS_KEY_EXCHANGE_SOME_XXDH_1_2_ENABLED
#endif

/* The handshake params structure has a set of fields called xxdh_psa which are used:
 * - by TLS 1.2 with `USE_PSA` to do ECDH or ECDHE;
 * - by TLS 1.3 to do ECDHE or FFDHE.
 * The following macros can be used to guard their declaration and use.
 */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) && \
    defined(MBEDTLS_USE_PSA_CRYPTO)
#define MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_1_2_ENABLED
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_1_2_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
#define MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED
#endif

#endif /* MBEDTLS_CONFIG_ADJUST_SSL_H */
