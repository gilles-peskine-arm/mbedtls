/*
 *  Host for offloaded functions
 *
 *  This program receives serialized function calls (see library/serialize.c)
 *  and executes them.
 *
 *  This program currently requires the serialization channel to be on file
 *  descriptors 3 for target-to-host and 4 for host-to-target.
 *  Set the environment variable FRONTEND_DEBUG to get debugging traces.
 *
 *  See library/serialize.c for a description of the serialization format.
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#define mbedtls_fprintf   fprintf
#include <unistd.h>
#endif

static int debug_verbose = 0;
#define DBG( fmt, ... )                                                 \
    ( (void) ( debug_verbose ?                                          \
               fprintf( stderr, "%s:%d:%s: " fmt "\n",                  \
                        __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__ ) : \
               0 ) )

#include "mbedtls/serialize.h"
#include "mbedtls/net_sockets.h"

/** State of the offloading frontend. */
typedef enum {
    MBEDTLS_SERIALIZE_STATUS_DEAD = 0, /**< The communication channel is broken */
    MBEDTLS_SERIALIZE_STATUS_OK = 1, /**< All conditions nominal */
    MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY = 2, /**< Out of memory for a function's parameters. Normal operation can resume after the next stack flush. */
    MBEDTLS_SERIALIZE_STATUS_EXITED = 3, /**< An exit command has been received */
} mbedtls_serialize_status_t;

/** An input or output to a serialized function.
 *
 * Inputs are kept as a linked list, outputs are kept in an array. There's
 * no deep reason for that, in retrospect an array would do fine for inputs. */
struct mbedtls_serialize_item;
typedef struct mbedtls_serialize_item {
    struct mbedtls_serialize_item *next; /**< Next input */
    size_t size; /**< Size of the following data in bytes */
    /* followed by the actual data */
} mbedtls_serialize_item_t;

/** Specialization of mbedtls_serialize_item_t with enough room for
 * data for a uint32. */
typedef struct {
    mbedtls_serialize_item_t meta;
    unsigned char data[4];
} mbedtls_serialize_uint32_t;

static void *item_buffer( mbedtls_serialize_item_t *item )
{
    return( (unsigned char*) item + sizeof( *item ) );
}

static uint16_t item_int16( mbedtls_serialize_item_t *item )
{
    uint8_t *buffer = item_buffer( item );
    return( buffer[0] << 8 | buffer[1] );
}

static uint16_t item_int32( mbedtls_serialize_item_t *item )
{
    uint8_t *buffer = item_buffer( item );
    return( buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3] );
}

/**< Allocate an item with length bytes. Return NULL on failure. */
static mbedtls_serialize_item_t *alloc_item( size_t length )
{
    mbedtls_serialize_item_t *item;
    item = mbedtls_calloc( sizeof( mbedtls_serialize_item_t ) + length, 1 );
    if( item != NULL )
    {
        item->size = length;
    }
    return( item );
}

static void set_item_int16( mbedtls_serialize_item_t *item, uint16_t value )
{
    uint8_t *buffer = item_buffer( item );
    buffer[0] = value >> 8 & 0xff;
    buffer[1] = value & 0xff;
}

static void set_item_int32( mbedtls_serialize_item_t *item, uint32_t value )
{
    uint8_t *buffer = item_buffer( item );
    buffer[0] = value >> 24 & 0xff;
    buffer[1] = value >> 16 & 0xff;
    buffer[2] = value >> 8 & 0xff;
    buffer[3] = value & 0xff;
}

/** Offloading context
 *
 * This data structure represents one connection to a target.
 */
typedef struct {
    int read_fd; /**< File descriptor for input from the target */
    int write_fd; /**< File descriptor for output to the target */
    mbedtls_serialize_item_t *stack; /**< Stack of inputs */
    mbedtls_serialize_status_t status; /**< Frontend status */
} mbedtls_serialize_context_t;

/** Write data on the serialization channel.
 * Any errors are fatal. */
static int mbedtls_serialize_write( mbedtls_serialize_context_t *ctx,
                                    uint8_t *buffer, size_t length )
{
    ssize_t result;
    do {
        result = write( ctx->write_fd, buffer, length );
        if( result < 0 )
        {
            perror( "Serialization write error" );
            return( MBEDTLS_ERR_SERIALIZE_SEND );
        }
        length -= result;
        buffer += result;
    } while( length > 0 );
    return( 0 );
}

/** Read exactly length bytes from the serialization channel.
 * Any errors are fatal. */
static int mbedtls_serialize_read( mbedtls_serialize_context_t *ctx,
                                   uint8_t *buffer, size_t length )
{
    ssize_t result;
    do {
        result = read( ctx->read_fd, buffer, length );
        if( result < 0 )
        {
            perror( "Serialization read error" );
            return( MBEDTLS_ERR_SERIALIZE_RECEIVE );
        }
        length -= result;
        buffer += result;
    } while( length > 0 );
    return( 0 );
}

/**< Discard all items on the stack and free them. */
static void mbedtls_serialize_discard_stack( mbedtls_serialize_context_t *ctx )
{
    mbedtls_serialize_item_t *item;
    while( ctx->stack != NULL )
    {
        item = ctx->stack;
        ctx->stack = item->next;
        mbedtls_free( item );
    }
}

#define CHECK_ARITY( min_arity )                                        \
    if( arity < ( min_arity ) )                                         \
    {                                                                   \
        DBG( "too few parameters: %u < %u", (unsigned) arity, (unsigned) ( min_arity ) ); \
        ret = MBEDTLS_ERR_SERIALIZE_BAD_INPUT;                          \
        break;                                                          \
    } else {}
#define CHECK_LENGTH( i, n )                                            \
    if( inputs[i]->size < ( n ) )                                       \
    {                                                                   \
        DBG( "parameter %u too short: %zu < %zu", (unsigned) i, inputs[i]->size, (size_t) ( n ) ); \
        ret = MBEDTLS_ERR_SERIALIZE_BAD_INPUT;                          \
        break;                                                          \
    } else {}
#define ALLOC_OUTPUT( i, length ) \
    if( ( outputs[i] = alloc_item( length ) ) == NULL )                 \
    {                                                                   \
        DBG( "failed to allocate %zu bytes for output %u", (size_t) ( length ), (unsigned) ( i ) );   \
        ret = MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED;                       \
        break;                                                          \
    } else {}

/** Execute an offloaded function.
 *
 * @param ctx       Offloading contecxt
 * @param function  Function to execute (MBEDTLS_SERIALIZE_FUNCTION_xxx)
 * @param outputs   Array[16] of outputs. Initially all-null. On return,
 *                  for a function with N outputs, positions 0 to N-1 will
 *                  be filled with output parameters allocated with alloc_item.
 * @return status (0 for ok, MBEDTLS_ERR_xxx on error)
 */
static uint32_t mbedtls_serialize_perform( mbedtls_serialize_context_t *ctx,
                                           uint32_t function,
                                           mbedtls_serialize_item_t **outputs )
{
    mbedtls_serialize_item_t *inputs[16] = {0};
    mbedtls_serialize_item_t *item;
    size_t arity;
    int ret;

    for( arity = 0, item = ctx->stack;
         arity < ( ( function & 0x0000f0 ) >> 4 ) && item != NULL;
         arity++, item = item->next )
    {
        inputs[arity] = item;
    }
    DBG( "arity=%zu", arity );

    switch( function )
    {
    case MBEDTLS_SERIALIZE_FUNCTION_EXIT:
        ret = 0;
        ctx->status = MBEDTLS_SERIALIZE_STATUS_EXITED;
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_ECHO:
    {
        CHECK_ARITY( 1 );
        ALLOC_OUTPUT( 0, inputs[0]->size );
        DBG( "executing echo" );
        memcpy( item_buffer( outputs[0] ), item_buffer( inputs[0] ), inputs[0]->size );
        ret = 0;
        break;
    }

    case MBEDTLS_SERIALIZE_FUNCTION_SOCKET:
        CHECK_ARITY( 3 ); // host, port, proto_and_mode
        CHECK_LENGTH( 2, 2 ); // proto_and_mode
        {
            char *host = item_buffer( inputs[0] );
            char *port = item_buffer( inputs[1] );
            uint16_t proto = item_int16( inputs[2] );
            int is_bind =
                ( ( proto & MBEDTLS_SERIALIZE_SOCKET_DIRECTION_MASK ) ==
                  MBEDTLS_SERIALIZE_SOCKET_BIND );
            mbedtls_net_context net_ctx;
            ALLOC_OUTPUT( 0, 2 ); // fd
            proto &= ~MBEDTLS_SERIALIZE_SOCKET_DIRECTION_MASK;
            if( is_bind )
            {
                DBG( "executing socket/bind" );
                ret = mbedtls_net_bind( &net_ctx, host, port, proto );
            }
            else
            {
                DBG( "executing socket/connect" );
                ret = mbedtls_net_connect( &net_ctx, host, port, proto );
            }
            if( ret == 0 )
            {
                DBG( "socket -> fd %d", (int)net_ctx.fd );
                set_item_int16( outputs[0], net_ctx.fd );
            }
        }
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_ACCEPT:
        CHECK_ARITY( 2 );
        CHECK_LENGTH( 0, 2 ); // socket_fd
        CHECK_LENGTH( 1, 4 ); // buffer_size
        {
            mbedtls_net_context bind_ctx = { item_int16( inputs[0] ) };
            uint32_t buffer_size = item_int32( inputs[1] );
            mbedtls_net_context client_ctx;
            size_t ip_len;
            ALLOC_OUTPUT( 0, 2 ); // client_fd
            ALLOC_OUTPUT( 1, buffer_size ); // client_ip
            DBG( "executing accept fd=%d", (int) bind_ctx.fd );
            ret = mbedtls_net_accept( &bind_ctx, &client_ctx,
                                      item_buffer( outputs[1] ), outputs[1]->size,
                                      &ip_len );
            if( ret == 0 )
            {
                DBG( "accept -> fd %d", (int) client_ctx.fd );
                set_item_int16( outputs[0], client_ctx.fd );
                outputs[1]->size = ip_len;
            }
        }
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_SET_BLOCK:
        CHECK_ARITY( 2 );
        CHECK_LENGTH( 0, 2 ); // fd
        CHECK_LENGTH( 1, 2 ); // mode
        {
            mbedtls_net_context ctx = { item_int16( inputs[0] ) };
            uint16_t mode = item_int16( inputs[1] );
            DBG( "executing set_block fd=%d mode=0x%04x", (int) ctx.fd, (unsigned) mode );
            switch( mode )
            {
            case MBEDTLS_SERIALIZE_BLOCK_BLOCK:
                ret = mbedtls_net_set_block( &ctx );
                break;
            case MBEDTLS_SERIALIZE_BLOCK_NONBLOCK:
                ret = mbedtls_net_set_nonblock( &ctx );
                break;
            default:
                ret = MBEDTLS_ERR_SERIALIZE_BAD_INPUT;
                break;
            }
        }
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_RECV:
        CHECK_ARITY( 3 );
        CHECK_LENGTH( 0, 2 ); // fd
        CHECK_LENGTH( 1, 4 ); // len
        CHECK_LENGTH( 2, 4 ); // timeout
        {
            mbedtls_net_context ctx = { item_int16( inputs[0] ) };
            uint32_t len = item_int32( inputs[1] );
            uint32_t timeout = item_int32( inputs[2] );
            ALLOC_OUTPUT( 0 , len ); // data
            if( timeout == MBEDTLS_SERIALIZE_TIMEOUT_INFINITE )
            {
                DBG( "executing recv fd=%u len=%u", (int) ctx.fd, (unsigned) len );
                ret = mbedtls_net_recv( &ctx, item_buffer( outputs[0] ), len );
            }
            else
            {
                DBG( "executing recv_timeout fd=%u len=%u timeout=%u", (unsigned) ctx.fd, (unsigned) len, (unsigned) timeout );
                ret = mbedtls_net_recv_timeout( &ctx,
                                                item_buffer( outputs[0] ), len,
                                                timeout );
            }
            if( ret >= 0 )
            {
                DBG( "received %zu bytes on fd=%d", (size_t) ret, (int) ctx.fd );
                outputs[0]->size = ret;
                ret = 0;
            }
        }
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_SEND:
        CHECK_ARITY( 2 );
        CHECK_LENGTH( 0, 2 ); // fd
        {
            mbedtls_net_context ctx = { item_int16( inputs[0] ) };
            size_t len = inputs[1]->size;
            unsigned char *buf = item_buffer( inputs[1] );
            ALLOC_OUTPUT( 0 , 4 ); // sent_len
            DBG( "executing send fd=%u len=%zu", (int) ctx.fd, len );
            ret = mbedtls_net_send( &ctx, buf, len );
            if( ret >= 0 )
            {
                DBG( "sent %zu bytes on fd=%d", (size_t) ret, (int) ctx.fd );
                set_item_int32( outputs[0], ret );
                ret = 0;
            }
        }
        break;

    case MBEDTLS_SERIALIZE_FUNCTION_SHUTDOWN:
        CHECK_ARITY( 1 );
        CHECK_LENGTH( 0, 2 ); // fd
        {
            mbedtls_net_context ctx = { item_int16( inputs[0] ) };
            DBG( "executing shutdown fd=%d", (int) ctx.fd );
            mbedtls_net_free( &ctx );
            ret = 0;
        }
        break;

    default:
        DBG( "unknown function 0x%06x", function );
        ret = MBEDTLS_ERR_SERIALIZE_BAD_INPUT;
        break;
    }

    mbedtls_serialize_discard_stack( ctx );
    return( ret );
}

/** Send one result (function output). */
static int mbedtls_serialize_send_result( mbedtls_serialize_context_t *ctx,
                                          uint8_t *buffer, size_t length )
{
    int ret;
    uint8_t header[4];
    if( length > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH )
    {
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_OUTPUT );
    }
    header[0] = MBEDTLS_SERIALIZE_TYPE_RESULT;
    header[1] = length >> 16 & 0xff;
    header[2] = length >> 8 & 0xff;
    header[3] = length & 0xff;
    if( (ret = mbedtls_serialize_write( ctx, header, sizeof( header ) ) ) != 0 )
        return( ret );
    return( mbedtls_serialize_write( ctx, buffer, length ) );
}

/** Read one message from the serialization channel and process it.
 *
 * For a push message, push the input parameter onto the stack.
 * For an execute message, execute the function and send the results.
 *
 * If the channel is dead (as indicated by ctx->status), do nothing.
 * If ctx->status == MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY, ignore
 * parameters and reply MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED to the next
 * function then set the status back to OK.
 * In case of any I/O error, set ctx->status to
 * MBEDTLS_SERIALIZE_STATUS_DEAD. */
static int mbedtls_serialize_pull( mbedtls_serialize_context_t *ctx )
{
    int ret;
    uint8_t header[4];
    if( ctx->status == MBEDTLS_SERIALIZE_STATUS_DEAD )
    {
        DBG( "already dead" );
        return( MBEDTLS_ERR_SERIALIZE_RECEIVE );
    }
    if( ( ret = mbedtls_serialize_read( ctx, header, sizeof( header ) ) ) != 0 )
    {
        DBG( "receive failure -> dead" );
        ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
        return( ret );
    }
    switch( header[0] )
    {
    case MBEDTLS_SERIALIZE_TYPE_PUSH:
    {
        size_t length = header[1] << 16 | header[2] << 8 | header[3];
        mbedtls_serialize_item_t *item;
        DBG( "received push length=%zu", length );
        if( ctx->status == MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY )
        {
            /* While we're out of memory, keep reading arguments but discard
               them. */
            while( length > sizeof( header ) )
            {
                if( ( ret = mbedtls_serialize_read( ctx, header, sizeof( header ) ) ) != 0 )
                {
                    DBG( "failed to read input with %zu bytes remaining -> dead", length );
                    ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
                    return( ret );
                }
                length -= sizeof( header );
            }
            if( ( ret = mbedtls_serialize_read( ctx, header, length ) ) != 0 )
            {
                DBG( "failed to read input with %zu bytes remaining -> dead", length );
                ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
                return( ret );
            }
            return( MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED );
        }
        item = alloc_item( length );
        if( item == NULL )
        {
            DBG( "failed to allocate %zu bytes for input", length );
            ctx->status = MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY;
            return( MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED );
        }
        if( ( ret = mbedtls_serialize_read( ctx, item_buffer( item ), length ) ) != 0 )
        {
            DBG( "failed to read %zu-byte input -> dead", length );
            ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
            return( ret );
        }
        DBG( "successfully read %zu-byte input", length );
        item->next = ctx->stack;
        ctx->stack = item;
        return( 0 );
    }

    case MBEDTLS_SERIALIZE_TYPE_EXECUTE:
    {
        uint32_t function = header[1] << 16 | header[2] << 8 | header[3];
        uint32_t status;
        mbedtls_serialize_uint32_t status_item = {{NULL, 4}, {0}};
        uint8_t *status_data = item_buffer( &status_item.meta );
        mbedtls_serialize_item_t *outputs[1 + 16] = {&status_item.meta};
        size_t i;
        DBG( "executing function 0x%06x", function );
        if( ctx->status == MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY )
        {
            /* Send an out-of-memory status */
            DBG( "already out of memory" );
            status = MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED;
        }
        else
        {
            status = mbedtls_serialize_perform( ctx, function, outputs + 1 );
        }
        DBG( "status = 0x%08x", status );
        status_data[0] = status >> 24 & 0xff;
        status_data[1] = status >> 16 & 0xff;
        status_data[2] = status >> 8 & 0xff;
        status_data[3] = status & 0xff;
        for( i = 0; i < sizeof( outputs ) / sizeof( *outputs ) && outputs[i] != NULL ; i++ )
        {
            DBG( "sending result %zu (%zu bytes)", i, outputs[i]->size );
            ret = mbedtls_serialize_send_result( ctx, item_buffer( outputs[i] ),
                                                 outputs[i]->size );
            if( ret != 0 )
            {
                DBG( "sending result %zu failed -> dead", i );
                ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
                break;
            }
        }
        for( i = 1; i < sizeof( outputs ) / sizeof( *outputs ) && outputs[i] != NULL ; i++ )
        {
            mbedtls_free( outputs[i] );
        }
        return( ret );
    }

    default:
        ctx->status = MBEDTLS_SERIALIZE_STATUS_DEAD;
        fprintf( stderr, "Bad type for serialized data: 0x%02x\n", header[0] );
        return( MBEDTLS_ERR_SERIALIZE_BAD_INPUT );
    }
}

void mbedtls_serialize_frontend( mbedtls_serialize_context_t *ctx )
{
    while( ctx->status == MBEDTLS_SERIALIZE_STATUS_OK ||
           ctx->status == MBEDTLS_SERIALIZE_STATUS_OUT_OF_MEMORY )
    {
        (void) mbedtls_serialize_pull( ctx );
    }
    close( ctx->read_fd );
    close( ctx->write_fd );
}

int main( )
{
    mbedtls_serialize_context_t ctx = {0};
    ctx.read_fd = 3;
    ctx.write_fd = 4;
    ctx.status = MBEDTLS_SERIALIZE_STATUS_OK;
    if( getenv( "FRONTEND_DEBUG" ) )
        debug_verbose = 1;
    mbedtls_serialize_frontend( &ctx );
    return( ctx.status != MBEDTLS_SERIALIZE_STATUS_EXITED );
}
