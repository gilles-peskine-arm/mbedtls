/**
 * \file ecc_contexts.h
 *
 * \brief Operation contexts for ECC-based mechanisms.
 *
 * \note The contents of this file are not part of the stable interface of
 *       the library. This file defines the implementation of structure
 *       types. These types are not part of the API, but they are part
 *       of the ABI, so the library SO version must be incremented when
 *       the types change.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_OPAQUE_ECC_CONTEXTS_H
#define MBEDTLS_OPAQUE_ECC_CONTEXTS_H
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include "mbedtls/opaque/mpi_contexts.h"

#include "mbedtls/md.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Note: when adding a new curve:
 * - Add it at the end of this enum, otherwise you'll break the ABI by
 *   changing the numerical value for existing curves.
 * - Increment MBEDTLS_ECP_DP_MAX below if needed.
 * - Update the calculation of MBEDTLS_ECP_MAX_BITS below.
 * - Add the corresponding MBEDTLS_ECP_DP_xxx_ENABLED macro definition to
 *   mbedtls_config.h.
 * - List the curve as a dependency of MBEDTLS_ECP_C and
 *   MBEDTLS_ECDSA_C if supported in check_config.h.
 * - Add the curve to the appropriate curve type macro
 *   MBEDTLS_ECP_yyy_ENABLED above.
 * - Add the necessary definitions to ecp_curves.c.
 * - Add the curve to the ecp_supported_curves array in ecp.c.
 * - Add the curve to applicable profiles in x509_crt.c.
 * - Add the curve to applicable presets in ssl_tls.c.
 */
enum mbedtls_ecp_group_id {
    MBEDTLS_ECP_DP_NONE = 0,       /*!< Curve not defined. */
    MBEDTLS_ECP_DP_SECP192R1,      /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP512R1,        /*!< Domain parameters for 512-bit Brainpool curve. */
    MBEDTLS_ECP_DP_CURVE25519,     /*!< Domain parameters for Curve25519. */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< Domain parameters for 192-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< Domain parameters for 224-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< Domain parameters for 256-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_CURVE448,       /*!< Domain parameters for Curve448. */
};

/**
 * The number of supported curves, plus one for #MBEDTLS_ECP_DP_NONE.
 */
#define MBEDTLS_ECP_DP_MAX     14

struct mbedtls_ecp_point {
    struct mbedtls_mpi MBEDTLS_PRIVATE(X);          /*!< The X coordinate of the ECP point. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(Y);          /*!< The Y coordinate of the ECP point. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(Z);          /*!< The Z coordinate of the ECP point. */
};

struct mbedtls_ecp_group {
    enum mbedtls_ecp_group_id id;    /*!< An internal group identifier. */
    struct mbedtls_mpi P;              /*!< The prime modulus of the base field. */
    struct mbedtls_mpi A;              /*!< For Short Weierstrass: \p A in the equation. Note that
                                     \p A is not set to the authentic value in some cases.
                                     Refer to detailed description of ::mbedtls_ecp_group if
                                     using domain parameters in the structure.
                                     For Montgomery curves: <code>(A + 2) / 4</code>. */
    struct mbedtls_mpi B;              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    struct mbedtls_ecp_point G;        /*!< The generator of the subgroup used. */
    struct mbedtls_mpi N;              /*!< The order of \p G. */
    size_t pbits;               /*!< The number of bits in \p P.*/
    size_t nbits;               /*!< For Short Weierstrass: The number of bits in \p P.
                                     For Montgomery curves: the number of bits in the
                                     private keys. */
    /* End of public fields */

    unsigned int MBEDTLS_PRIVATE(h);             /*!< \internal 1 if the constants are static. */
    int(*MBEDTLS_PRIVATE(modp))(struct mbedtls_mpi *);  /*!< The function for fast pseudo-reduction
                                                    mod \p P (see above).*/
    int(*MBEDTLS_PRIVATE(t_pre))(struct mbedtls_ecp_point *, void *);   /*!< Unused. */
    int(*MBEDTLS_PRIVATE(t_post))(struct mbedtls_ecp_point *, void *);  /*!< Unused. */
    void *MBEDTLS_PRIVATE(t_data);               /*!< Unused. */
    struct mbedtls_ecp_point *MBEDTLS_PRIVATE(T);       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t MBEDTLS_PRIVATE(T_size);              /*!< The number of dynamic allocated pre-computed points. */
};

struct mbedtls_ecp_keypair {
    struct mbedtls_ecp_group MBEDTLS_PRIVATE(grp);      /*!<  Elliptic curve and base point     */
    struct mbedtls_mpi MBEDTLS_PRIVATE(d);              /*!<  our secret value                  */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Q);        /*!<  our public value                  */
};

enum mbedtls_ecdh_variant {
    MBEDTLS_ECDH_VARIANT_NONE = 0,   /*!< Implementation not defined. */
    MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0,/*!< The default Mbed TLS implementation */
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    MBEDTLS_ECDH_VARIANT_EVEREST     /*!< Everest implementation */
#endif
};

#if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
struct mbedtls_ecdh_context_mbed {
    struct mbedtls_ecp_group MBEDTLS_PRIVATE(grp);   /*!< The elliptic curve used. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(d);           /*!< The private key. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Q);     /*!< The public key. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Qp);    /*!< The value of the public key of the peer. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(z);           /*!< The shared secret. */
#if defined(MBEDTLS_ECP_RESTARTABLE)
    struct mbedtls_ecp_restart_ctx MBEDTLS_PRIVATE(rs); /*!< The restart context for EC computations. */
#endif
};
#endif

#if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
/**
 * Defines the ECDH implementation used.
 *
 * Later versions of the library may add new variants, therefore users should
 * not make any assumptions about them.
 */
typedef enum mbedtls_ecdh_variant mbedtls_ecdh_variant;

/**
 * The context used by the default ECDH implementation.
 *
 * Later versions might change the structure of this context, therefore users
 * should not make any assumptions about the structure of
 * mbedtls_ecdh_context_mbed.
 */
typedef struct mbedtls_ecdh_context_mbed mbedtls_ecdh_context_mbed;
#endif

struct mbedtls_ecdh_context {
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    struct mbedtls_ecp_group MBEDTLS_PRIVATE(grp);   /*!< The elliptic curve used. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(d);           /*!< The private key. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Q);     /*!< The public key. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Qp);    /*!< The value of the public key of the peer. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(z);           /*!< The shared secret. */
    int MBEDTLS_PRIVATE(point_format);        /*!< The format of point export in TLS messages. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Vi);    /*!< The blinding value. */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Vf);    /*!< The unblinding value. */
    struct mbedtls_mpi MBEDTLS_PRIVATE(_d);          /*!< The previous \p d. */
#if defined(MBEDTLS_ECP_RESTARTABLE)
    int MBEDTLS_PRIVATE(restart_enabled);        /*!< The flag for restartable mode. */
    struct mbedtls_ecp_restart_ctx MBEDTLS_PRIVATE(rs); /*!< The restart context for EC computations. */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#else
    uint8_t MBEDTLS_PRIVATE(point_format);       /*!< The format of point export in TLS messages
                                                    as defined in RFC 4492. */
    enum mbedtls_ecp_group_id MBEDTLS_PRIVATE(grp_id);/*!< The elliptic curve used. */
    enum mbedtls_ecdh_variant MBEDTLS_PRIVATE(var);   /*!< The ECDH implementation/structure used. */
    union {
        struct mbedtls_ecdh_context_mbed   MBEDTLS_PRIVATE(mbed_ecdh);
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        mbedtls_ecdh_context_everest MBEDTLS_PRIVATE(everest_ecdh);
#endif
    } MBEDTLS_PRIVATE(ctx);                      /*!< Implementation-specific context. The
                                                    context in use is specified by the \c var
                                                    field. */
#if defined(MBEDTLS_ECP_RESTARTABLE)
    uint8_t MBEDTLS_PRIVATE(restart_enabled);    /*!< The flag for restartable mode. Functions of
                                                    an alternative implementation not supporting
                                                    restartable mode must return
                                                    MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED error
                                                    if this flag is set. */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#endif /* MBEDTLS_ECDH_LEGACY_CONTEXT */
};

enum mbedtls_ecjpake_role {
    MBEDTLS_ECJPAKE_CLIENT = 0,         /**< Client                         */
    MBEDTLS_ECJPAKE_SERVER,             /**< Server                         */
    MBEDTLS_ECJPAKE_NONE,               /**< Undefined                      */
};

struct mbedtls_ecjpake_context {
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_type);          /**< Hash to use                    */
    struct mbedtls_ecp_group MBEDTLS_PRIVATE(grp);              /**< Elliptic curve                 */
    enum mbedtls_ecjpake_role MBEDTLS_PRIVATE(role);          /**< Are we client or server?       */
    int MBEDTLS_PRIVATE(point_format);                   /**< Format for point export        */

    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Xm1);              /**< My public key 1   C: X1, S: X3 */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Xm2);              /**< My public key 2   C: X2, S: X4 */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Xp1);              /**< Peer public key 1 C: X3, S: X1 */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Xp2);              /**< Peer public key 2 C: X4, S: X2 */
    struct mbedtls_ecp_point MBEDTLS_PRIVATE(Xp);               /**< Peer public key   C: Xs, S: Xc */

    struct mbedtls_mpi MBEDTLS_PRIVATE(xm1);                    /**< My private key 1  C: x1, S: x3 */
    struct mbedtls_mpi MBEDTLS_PRIVATE(xm2);                    /**< My private key 2  C: x2, S: x4 */

    struct mbedtls_mpi MBEDTLS_PRIVATE(s);                      /**< Pre-shared secret (passphrase) */
};

#ifdef __cplusplus
}
#endif

#endif /* ecc_contexts.h */
