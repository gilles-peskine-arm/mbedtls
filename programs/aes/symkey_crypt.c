#define _POSIX_C_SOURCE 200112L

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------

#include "mbedtls/build_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit

#include "mbedtls/cipher.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/cipher.h"

//----------------------------------------------------------------------------
//----------------- Defines -------------------------------------------------
//----------------------------------------------------------------------------
#define LOG_ERROR(fmt, ...)    printf("ERROR:"fmt, ##__VA_ARGS__)
// Test Failure (TF) define 
#define TF( func_call, error_label )    \
    if( (rc = (func_call)) != 0 )       \
        goto error_label
  
typedef mbedtls_cipher_info_t     cipher_info_t;
typedef mbedtls_cipher_context_t  cipher_context_t;

//----------------------------------------------------------------------------
//----------------- Defines -------------------------------------------------
//----------------------------------------------------------------------------

#if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_FS_IO)

int main( void )
{
    mbedtls_printf("MBEDTLS_CIPHER_C and/or MBEDTLS_MD_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit( 0 );
}
#else  // #if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_FS_IO)


static int usage( char ** argv)
{
    printf("\nUsage:\n");
    printf("  %s  [-d] [-e] -algo <algo> -mode <mode> -keyfile <keyfile> -ivfile <ivfile> -infile <infile> -outfile <outfile>\n", argv[0]);
    printf("where:\n");
    printf("  -d      : decrypt\n");
    printf("  -e      : encrypt\n");
    printf("  algo    : cipher algorithm (AES, CAMILLA, ARIA, etc)\n");
    printf("  mode    : cipher mode      (ECB, CBC, CTR, etc)\n");
    printf("  keyfile : key file\n");
    printf("  ivfile  : iv file\n");
    printf("  infile  : input file to be en/decrypted\n");
    printf("example:\n");
    printf("  %s \n", argv[0]);
    exit(-1);
}

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}


static uint8_t *util_file2bufAlloc(const char *path, size_t *size )
{
    FILE     *fp = NULL;
    uint8_t  *buf = NULL;
    size_t    bytes_read, fsize;


    //--------- code ----------------------------------------------------------
    if( (fp = fopen(path, "rb")) == NULL)
    {
        LOG_ERROR("%s(): Cannot open file %s\n",__func__, path);
        goto Fail;
    }
    // find the size of the file
    fseek(fp, 0, SEEK_END);
    fsize = ftell( fp);
    if ( (buf = (uint8_t*)malloc(fsize)) == NULL)
         goto Fail;

    // Move file pinter back to the beginning
    fseek(fp, 0, SEEK_SET);
    bytes_read = fread(buf, 1, fsize, fp);
    fclose(fp);
    if ( bytes_read != fsize )
        goto Fail;
    *size = fsize;
    return buf;

Fail:
    if( fp != NULL )
        fclose(fp);
    if ( buf != NULL )
        free(buf);
    LOG_ERROR("%s()\n", __func__);
    exit(-2);
    //return NULL;
}


int main(int argc, char *argv[])
{
    const cipher_info_t *cipher_info;
    cipher_context_t     cipher_ctx;
    FILE                *fout;
    const char          *fail_str;
    char                *arg;
    int                  i, rc = 0, mode, kbitlen;
    char                 infile[256], outfile[256], keyfile[256], ivfile[256];
    char                 algo[16], op_mode[16], cipher_string[32];
    uint8_t             * iv,*key,*m;
    uint8_t              output[1024];
    size_t               klen, ivlen, mlen, olen, ilen;
    size_t               offset, block_size;


    //--------- code ----------------------------------------------------------
    // Initialize with default values
    strcpy(algo, "AES");
    strcpy(op_mode, "CBC");
    infile[0] = 0;
    outfile[0] = 0;
    keyfile[0] = 0;
    ivfile[0] = 0;

    // parse the argument
    for (i = 1; i < argc - 1; i++) {
        arg = argv[i];
        // printf("arg='%s'\n", arg);

        if (strcmp(arg, "-e") == 0) {
            mode = MBEDTLS_ENCRYPT;
            continue;
        }
        if (strcmp(arg, "-d") == 0) { 
            mode = MBEDTLS_DECRYPT;
            continue;
        }

        if (i >= argc - 1) {
            LOG_ERROR("argument %s requires a value\n", arg);
            usage(argv);
        }

        if (strcmp(arg, "-algo") == 0) {
            snprintf(algo, sizeof(algo) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        if (strcmp(arg, "-mode") == 0) {
            snprintf(op_mode, sizeof(op_mode) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        if (strcmp(arg, "-keyfile") == 0) {
            snprintf(keyfile, sizeof(keyfile) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        if (strcmp(arg, "-ivfile") == 0) {
            snprintf(ivfile, sizeof(ivfile) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        if (strcmp(arg, "-infile") == 0) {
            snprintf(infile, sizeof(infile) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        if (strcmp(arg, "-outfile") == 0) {
            snprintf(outfile, sizeof(outfile) - 1, "%s", argv[i + 1]);
            i++;
            continue;
        }
        LOG_ERROR("unknown argument %s\n", arg);
        usage(argv);
    }
    if ((keyfile[0] == 0) || (ivfile[0] == 0) || (outfile[0] == 0) || (infile[0] == 0))  {
        LOG_ERROR("%s() key,iv,in or output file is not defined\n", __func__);
        usage(argv);
    }
    // load the data from the files
    key = util_file2bufAlloc(keyfile, &klen);
    iv  = util_file2bufAlloc(ivfile, &ivlen);
    m   = util_file2bufAlloc(infile, &mlen);

    // Sanity checks
    if ((fout = fopen(outfile, "wb+")) == NULL)
        goto fail_fopen;

    if (strcmp(infile, outfile) == 0) {
        mbedtls_fprintf(stderr, "input and output filenames must differ\n");
        goto cleanup;
    }

    // Create the cipher string
    kbitlen = klen*8;
    snprintf(cipher_string, sizeof(cipher_string), "%s-%d-%s", algo, kbitlen, op_mode);

    if ((cipher_info = mbedtls_cipher_info_from_string(cipher_string)) == NULL) {
        mbedtls_fprintf(stderr, "Cipher mode '%s' not found\n", cipher_string);
        usage(argv);
    }

    // prepare the block cipher
    mbedtls_cipher_init(&cipher_ctx);
    TF(   mbedtls_cipher_setup(&cipher_ctx, cipher_info)   , fail_setup);
    //if ((rc = mbedtls_cipher_setup(&cipher_ctx, cipher_info)) != 0)
    //    goto fail_setup;
    dump_buf("key: ", key, klen);
    dump_buf("iv:  ", iv, ivlen);
    dump_buf("m:   ", m, mlen);
    mbedtls_printf("mode=%d\n",mode); 
    mbedtls_printf("cipher=%s\n",cipher_string); 
    if ((rc = mbedtls_cipher_setkey(&cipher_ctx, key, kbitlen, mode)) != 0)
        goto fail_setkey;
    if ((rc = mbedtls_cipher_set_iv(&cipher_ctx, iv, 16)) != 0)
        goto fail_iv;
    if ((rc = mbedtls_cipher_reset(&cipher_ctx)) != 0)
        goto fail_reset;

    if ((block_size = mbedtls_cipher_get_block_size(&cipher_ctx)) == 0)
        goto fail_blocksz;

    if (mode == MBEDTLS_ENCRYPT) {
        for (offset = 0; offset < mlen; offset += block_size) {
            if ((mlen - offset) <  block_size)
                ilen = mlen - offset;
            else 
                ilen = block_size;

            if ((rc = mbedtls_cipher_update(&cipher_ctx, m + offset, ilen, output, &olen)) != 0)
                goto fail_update;
            //printf("update: offset=%d, ilen=%d, olen=%d\n", (int)offset, (int)ilen, (int)olen);

            if (fwrite(output, 1, olen, fout) != olen)
                goto fail_fwrite;
        }
        if ((rc = mbedtls_cipher_finish(&cipher_ctx, output, &olen)) != 0)
            goto fail_finish;
        //printf("finish: offset=%d, olen=%d\n", (int)offset, (int)olen);

        if (fwrite(output, 1, olen, fout) != olen)
            goto fail_fwrite;
    }
    if (mode == MBEDTLS_DECRYPT) {
        // Check the file size.
        if ((mlen < block_size) || (mlen % block_size != 0)) 
            goto fail_fsize;

        block_size = 7;
        for (offset = 0; offset < mlen; offset += block_size) {
            if ((mlen - offset) <  block_size)
                ilen = mlen - offset;
            else 
                ilen = block_size;

            if ((rc = mbedtls_cipher_update(&cipher_ctx, m + offset, ilen, output, &olen)) != 0)
                goto fail_update;
            //printf("update: offset=%d, ilen=%d, olen=%d\n", (int)offset, (int)ilen, (int)olen);

            if (fwrite(output, 1, olen, fout) != olen)
                goto fail_fwrite;;
        }
        if ((rc = mbedtls_cipher_finish(&cipher_ctx, output, &olen)) != 0)
            goto fail_finish;
        //printf("finish: offset=%d, olen=%d\n", (int)offset, (int)olen);

        if (fwrite(output, 1, olen, fout) != olen)
            goto fail_fwrite;
    }
    rc = 0;
    mbedtls_printf("Done...\n\n");
    goto cleanup;


// --- Error handling ---
fail_fwrite: fail_str = "write"; goto fail_file;
fail_fopen:  fail_str = "open";  goto fail_file;
fail_fsize:  fail_str = "size";
fail_file:
    mbedtls_fprintf(stderr, "file %s failure\n", fail_str);
    goto cleanup;

fail_setup:   fail_str = "setup";  goto fail_end;
fail_setkey:  fail_str = "setkey"; goto fail_end;
fail_iv:      fail_str = "iv";     goto fail_end;
fail_reset:   fail_str = "reset";  goto fail_end;
fail_update:  fail_str = "update"; goto fail_end;
fail_finish:  fail_str = "finish"; goto fail_end;
fail_blocksz: fail_str = "get_block_size"; goto fail_end;
fail_end:
    {
        char error_str[200];
        mbedtls_strerror( rc, error_str, 200 );
        mbedtls_fprintf(stderr, "mbedtls_cipher_%s() returned error code %d = '%s'\n", fail_str, rc, error_str);
    }


// --- Cleanup ---
cleanup:
    if (fout != NULL)
        fclose(fout);

    /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[6]. */
    for (i = 0; i < argc; i++) mbedtls_platform_zeroize(argv[i], strlen(argv[i]));

    mbedtls_platform_zeroize(key,    sizeof(key));
    mbedtls_platform_zeroize(m,      sizeof(m));
    mbedtls_platform_zeroize(output, sizeof(output));

    mbedtls_cipher_free(&cipher_ctx);
    mbedtls_exit(rc);
}
#endif /* MBEDTLS_CIPHER_C && MBEDTLS_MD_C && MBEDTLS_FS_IO */
