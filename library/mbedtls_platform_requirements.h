/**
 * \file mbedtls_platform_requirements.h
 *
 * \brief Declare macros that tell system headers what we expect of them.
 *
 * This file must be included before any system header, and so in particular
 * before build_info.h (which includes the user config, which may include
 * system headers).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H
#define MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H

#if !defined(_POSIX_C_SOURCE)
/* For standards-compliant access to
 * getaddrinfo(),
 * ... */
#define _POSIX_C_SOURCE 200112L
#endif

#if !defined(_XOPEN_SOURCE)
/* For standards-compliant access to
 * sockaddr_storage,
 * ... */
#define _XOPEN_SOURCE 600
#endif

#endif /* MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H */
