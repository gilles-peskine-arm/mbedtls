/* Minimum needed stuff from BearSSL inner.h and bearssl_block.h */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * The constant-time implementation is "bitsliced": the 128-bit state is
 * split over eight 32-bit words q* in the following way:
 *
 * -- Input block consists in 16 bytes:
 *    a00 a10 a20 a30 a01 a11 a21 a31 a02 a12 a22 a32 a03 a13 a23 a33
 * In the terminology of FIPS 197, this is a 4x4 matrix which is read
 * column by column.
 *
 * -- Each byte is split into eight bits which are distributed over the
 * eight words, at the same rank. Thus, for a byte x at rank k, bit 0
 * (least significant) of x will be at rank k in q0 (if that bit is b,
 * then it contributes "b << k" to the value of q0), bit 1 of x will be
 * at rank k in q1, and so on.
 *
 * -- Ranks given to bits are in "row order" and are either all even, or
 * all odd. Two independent AES states are thus interleaved, one using
 * the even ranks, the other the odd ranks. Row order means:
 *    a00 a01 a02 a03 a10 a11 a12 a13 a20 a21 a22 a23 a30 a31 a32 a33
 *
 * Converting input bytes from two AES blocks to bitslice representation
 * is done in the following way:
 * -- Decode first block into the four words q0 q2 q4 q6, in that order,
 * using little-endian convention.
 * -- Decode second block into the four words q1 q3 q5 q7, in that order,
 * using little-endian convention.
 * -- Call br_aes_ct_ortho().
 *
 * Converting back to bytes is done by using the reverse operations. Note
 * that br_aes_ct_ortho() is its own inverse.
 */

/*
 * Perform bytewise orthogonalization of eight 32-bit words. Bytes
 * of q0..q7 are spread over all words: for a byte x that occurs
 * at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in q[j]), the bit
 * of rank k in x (0 <= k <= 7) goes to q[k] at rank 8*i+j.
 *
 * This operation is an involution.
 */
void br_aes_ct_ortho(uint32_t *q);

/*
 * The AES S-box, as a bitsliced constant-time version. The input array
 * consists in eight 32-bit words; 32 S-box instances are computed in
 * parallel. Bits 0 to 7 of each S-box input (bit 0 is least significant)
 * are spread over the words 0 to 7, at the same rank.
 */
void br_aes_ct_bitslice_Sbox(uint32_t *q);

/*
 * Like br_aes_bitslice_Sbox(), but for the inverse S-box.
 */
void br_aes_ct_bitslice_invSbox(uint32_t *q);

/*
 * Compute AES encryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block encryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_encrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * Compute AES decryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block decryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_decrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * AES key schedule, constant-time version. skey[] is filled with n+1
 * 128-bit subkeys, where n is the number of rounds (10 to 14, depending
 * on key size). The number of rounds is returned. If the key size is
 * invalid (not 16, 24 or 32), then 0 is returned.
 */
unsigned br_aes_ct_keysched(uint32_t *comp_skey,
	const void *key, size_t key_len);

/*
 * Expand AES subkeys as produced by br_aes_ct_keysched(), into
 * a larger array suitable for br_aes_ct_bitslice_encrypt() and
 * br_aes_ct_bitslice_decrypt().
 */
void br_aes_ct_skey_expand(uint32_t *skey,
	unsigned num_rounds, const uint32_t *comp_skey);

/*
 * The constant-time implementation is "bitsliced": the 128-bit state is
 * split over eight 32-bit words q* in the following way:
 *
 * -- Input block consists in 16 bytes:
 *    a00 a10 a20 a30 a01 a11 a21 a31 a02 a12 a22 a32 a03 a13 a23 a33
 * In the terminology of FIPS 197, this is a 4x4 matrix which is read
 * column by column.
 *
 * -- Each byte is split into eight bits which are distributed over the
 * eight words, at the same rank. Thus, for a byte x at rank k, bit 0
 * (least significant) of x will be at rank k in q0 (if that bit is b,
 * then it contributes "b << k" to the value of q0), bit 1 of x will be
 * at rank k in q1, and so on.
 *
 * -- Ranks given to bits are in "row order" and are either all even, or
 * all odd. Two independent AES states are thus interleaved, one using
 * the even ranks, the other the odd ranks. Row order means:
 *    a00 a01 a02 a03 a10 a11 a12 a13 a20 a21 a22 a23 a30 a31 a32 a33
 *
 * Converting input bytes from two AES blocks to bitslice representation
 * is done in the following way:
 * -- Decode first block into the four words q0 q2 q4 q6, in that order,
 * using little-endian convention.
 * -- Decode second block into the four words q1 q3 q5 q7, in that order,
 * using little-endian convention.
 * -- Call br_aes_ct_ortho().
 *
 * Converting back to bytes is done by using the reverse operations. Note
 * that br_aes_ct_ortho() is its own inverse.
 */

/*
 * Perform bytewise orthogonalization of eight 32-bit words. Bytes
 * of q0..q7 are spread over all words: for a byte x that occurs
 * at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in q[j]), the bit
 * of rank k in x (0 <= k <= 7) goes to q[k] at rank 8*i+j.
 *
 * This operation is an involution.
 */
void br_aes_ct_ortho(uint32_t *q);

/*
 * The AES S-box, as a bitsliced constant-time version. The input array
 * consists in eight 32-bit words; 32 S-box instances are computed in
 * parallel. Bits 0 to 7 of each S-box input (bit 0 is least significant)
 * are spread over the words 0 to 7, at the same rank.
 */
void br_aes_ct_bitslice_Sbox(uint32_t *q);

/*
 * Like br_aes_bitslice_Sbox(), but for the inverse S-box.
 */
void br_aes_ct_bitslice_invSbox(uint32_t *q);

/*
 * Compute AES encryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block encryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_encrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * Compute AES decryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block decryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_decrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * AES key schedule, constant-time version. skey[] is filled with n+1
 * 128-bit subkeys, where n is the number of rounds (10 to 14, depending
 * on key size). The number of rounds is returned. If the key size is
 * invalid (not 16, 24 or 32), then 0 is returned.
 */
unsigned br_aes_ct_keysched(uint32_t *comp_skey,
	const void *key, size_t key_len);

/*
 * Expand AES subkeys as produced by br_aes_ct_keysched(), into
 * a larger array suitable for br_aes_ct_bitslice_encrypt() and
 * br_aes_ct_bitslice_decrypt().
 */
void br_aes_ct_skey_expand(uint32_t *skey,
	unsigned num_rounds, const uint32_t *comp_skey);



/* Same layout as mbedtls_aes_context */
typedef struct {
    int num_rounds;
    size_t rk_offset;
    uint32_t skey[60];
} br_aes_ct_cbcenc_keys;

/* Same layout as mbedtls_aes_context */
typedef struct {
    int num_rounds;
    size_t rk_offset;
    uint32_t skey[60];
} br_aes_ct_cbcdec_keys;

/**
 * \brief Context initialisation (key schedule) for AES CBC encryption
 * (`aes_ct` implementation).
 *
 * \param ctx   context to initialise.
 * \param key   secret key.
 * \param len   secret key length (in bytes).
 */
void br_aes_ct_cbcenc_init(br_aes_ct_cbcenc_keys *ctx,
        const void *key, size_t len);

/**
 * \brief Context initialisation (key schedule) for AES CBC decryption
 * (`aes_ct` implementation).
 *
 * \param ctx   context to initialise.
 * \param key   secret key.
 * \param len   secret key length (in bytes).
 */
void br_aes_ct_cbcdec_init(br_aes_ct_cbcdec_keys *ctx,
        const void *key, size_t len);

/**
 * \brief CBC encryption with AES (`aes_ct` implementation).
 *
 * \param ctx    context (already initialised).
 * \param iv     IV (updated).
 * \param data   data to encrypt (updated).
 * \param len    data length (in bytes, MUST be multiple of 16).
 */
void br_aes_ct_cbcenc_run(const br_aes_ct_cbcenc_keys *ctx, void *iv,
        void *data, size_t len);

/**
 * \brief CBC decryption with AES (`aes_ct` implementation).
 *
 * \param ctx    context (already initialised).
 * \param iv     IV (updated).
 * \param data   data to decrypt (updated).
 * \param len    data length (in bytes, MUST be multiple of 16).
 */
void br_aes_ct_cbcdec_run(const br_aes_ct_cbcdec_keys *ctx, void *iv,
        void *data, size_t len);

static inline void
br_enc32le(void *dst, uint32_t x)
{
#if BR_LE_UNALIGNED
        ((br_union_u32 *)dst)->u = x;
#else
        unsigned char *buf;

        buf = dst;
        buf[0] = (unsigned char)x;
        buf[1] = (unsigned char)(x >> 8);
        buf[2] = (unsigned char)(x >> 16);
        buf[3] = (unsigned char)(x >> 24);
#endif
}

static inline uint32_t
br_dec32le(const void *src)
{
#if BR_LE_UNALIGNED
        return ((const br_union_u32 *)src)->u;
#else
        const unsigned char *buf;

        buf = src;
        return (uint32_t)buf[0]
                | ((uint32_t)buf[1] << 8)
                | ((uint32_t)buf[2] << 16)
                | ((uint32_t)buf[3] << 24);
#endif
}
