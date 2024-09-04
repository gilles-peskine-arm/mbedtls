# Test that SSL sample programs can interoperate with OpenSSL and GnuTLS.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

: ${PROGRAMS_DIR:=../programs/ssl}

requires_protocol_version tls12
run_test    "Sample: ssl_client1, openssl server, TLS 1.2" \
            -P 4433 \
            "$O_SRV -tls1_2" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -c "Protocol.*TLSv1.2" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: ssl_client1, gnutls server, TLS 1.2" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "Version: TLS1.2" \
            -c "<TD>Protocol version:</TD><TD>TLS1.2</TD>" \
            -S "Error" \
            -C "error"

requires_protocol_version tls13
requires_openssl_tls1_3
run_test    "Sample: ssl_client1, openssl server, TLS 1.3" \
            -P 4433 \
            "$O_NEXT_SRV -tls1_3" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -c "New, TLSv1.3, Cipher is" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls13
run_test    "Sample: ssl_client1, gnutls server, TLS 1.3" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "Version: TLS1.3" \
            -c "<TD>Protocol version:</TD><TD>TLS1.3</TD>" \
            -S "Error" \
            -C "error"

# In principle, this test case should work with OpenSSL 1.0.2g (which is
# our reference version of $OPENSSL at this time). However, on my machine,
# dtls_client connects to localhost using IPv6, but OpenSSL 1.0.2.g only
# accepts IPv4 connections. So use OPENSSL_NEXT, which is at least 1.1.1
# and should be IPv6-aware.
requires_protocol_version dtls12
requires_openssl_next
run_test    "Sample: dtls_client, openssl server, DTLS 1.2" \
            -P 4433 \
            "$O_NEXT_SRV -dtls1_2" \
            "$PROGRAMS_DIR/dtls_client" \
            0 \
            -s "Echo this" \
            -s "DONE" \
            -c "Echo this" \
            -c "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -S "ERROR" \
            -C "error"

requires_protocol_version dtls12
run_test    "Sample: dtls_client, gnutls server, DTLS 1.2" \
            -P 4433 \
            "$G_SRV -u --echo --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2" \
            "$PROGRAMS_DIR/dtls_client" \
            0 \
            -s "Server listening" \
            -s "[1-9][0-9]* bytes command:" \
            -c "Echo this" \
            -c "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -S "Error" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: mini_client, openssl server, TLS 1.2" \
            -P 4433 \
            "$O_SRV -tls1_2" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "GET / HTTP/1.0" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: mini_client, gnutls server, TLS 1.2" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "Version: TLS1.2" \
            -S "Error" \
            -C "error"

requires_protocol_version tls13
requires_openssl_tls1_3
run_test    "Sample: mini_client, openssl server, TLS 1.3" \
            -P 4433 \
            "$O_NEXT_SRV -tls1_3" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "GET / HTTP/1.0" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls13
run_test    "Sample: mini_client, gnutls server, TLS 1.3" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "Version: TLS1.3" \
            -S "Error" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: ssl_server, openssl client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$O_CLI -tls1_2" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Protocol.*TLSv1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls12
run_test    "Sample: ssl_server, gnutls client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 localhost" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Description:.*TLS1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
requires_openssl_tls1_3
run_test    "Sample: ssl_server, openssl client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$O_NEXT_CLI -tls1_3" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "New, TLSv1.3, Cipher is" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
run_test    "Sample: ssl_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls12
run_test    "Sample: ssl_fork_server, openssl client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$O_CLI -tls1_2" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Protocol.*TLSv1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls12
run_test    "Sample: ssl_fork_server, gnutls client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 localhost" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Description:.*TLS1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
requires_openssl_tls1_3
run_test    "Sample: ssl_fork_server, openssl client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$O_NEXT_CLI -tls1_3" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "New, TLSv1.3, Cipher is" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
run_test    "Sample: ssl_fork_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls12
run_test    "Sample: ssl_pthread_server, openssl client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$O_CLI -tls1_2" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Protocol.*TLSv1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls12
run_test    "Sample: ssl_pthread_server, gnutls client, TLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 localhost" \
            0 \
            -s "Successful connection using: TLS-" \
            -c "Description:.*TLS1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
requires_openssl_tls1_3
run_test    "Sample: ssl_pthread_server, openssl client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$O_NEXT_CLI -tls1_3" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "New, TLSv1.3, Cipher is" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
run_test    "Sample: ssl_pthread_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$G_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

requires_protocol_version dtls12
run_test    "Sample: dtls_server, openssl client, DTLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/dtls_server" \
            "$O_CLI -dtls1_2" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "Protocol.*TLSv1.2" \
            -S "error" \
            -C "ERROR"

requires_protocol_version dtls12
run_test    "Sample: dtls_server, gnutls client, DTLS 1.2" \
            -P 4433 \
            "$PROGRAMS_DIR/dtls_server" \
            "$G_CLI -u --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 localhost" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "Description:.*DTLS1.2" \
            -S "error" \
            -C "ERROR"
