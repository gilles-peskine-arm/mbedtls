# Test that SSL sample programs can interoperate with each other
# and with OpenSSL and GnuTLS.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

: ${PROGRAMS_DIR:=../programs/ssl}

run_test    "Sample: ssl_client1, ssl_server2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server2" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

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
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_client1, openssl server, TLS 1.3" \
            -P 4433 \
            "$O_NEXT_SRV -tls1_3" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -c "New, TLSv1.3, Cipher is" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls13
requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_client1, gnutls server, TLS 1.3" \
            -P 4433 \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "Version: TLS1.3" \
            -c "<TD>Protocol version:</TD><TD>TLS1.3</TD>" \
            -S "Error" \
            -C "error"

requires_protocol_version tls13
requires_openssl_tls1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_client1, openssl server, TLS 1.3, no middlebox compatibility" \
            -P 4433 \
            "$O_NEXT_SRV -tls1_3 -no_middlebox" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -c "New, TLSv1.3, Cipher is" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls13
requires_gnutls_tls1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_client1, gnutls server, TLS 1.3, no middlebox compatibility" \
            -P 4433 \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "Version: TLS1.3" \
            -c "<TD>Protocol version:</TD><TD>TLS1.3</TD>" \
            -S "Error" \
            -C "error"

# The server complains of extra data after it closes the connection
# because the client keeps sending data, so the server receives
# more application data when it expects a new handshake. We consider
# the test a success if both sides have sent and received application
# data, no matter what happens afterwards.
run_test    "Sample: dtls_client, ssl_server2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server2 dtls=1 server_addr=localhost" \
            "$PROGRAMS_DIR/dtls_client" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -C "error"

requires_protocol_version dtls12
run_test    "Sample: dtls_client, openssl server, DTLS 1.2" \
            -P 4433 \
            "$O_SRV -dtls1_2" \
            "$PROGRAMS_DIR/dtls_client" \
            0 \
            -s "Echo this" \
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

run_test    "Sample: mini_client, ssl_server2, PSK" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server2 psk_identity=Client_identity psk=000102030405060708090a0b0c0d0e0f" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: mini_client, openssl server, TLS 1.2 PSK" \
            -P 4433 \
            "$O_SRV -tls1_2 -allow_no_dhe_kex -nocert \
                    -psk_identity Client_identity -psk 000102030405060708090a0b0c0d0e0f" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "GET / HTTP/1.0" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls12
run_test    "Sample: mini_client, gnutls server, TLS 1.2 PSK" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:+AES-128-CCM-8:+AES-256-CCM-8:-VERS-TLS-ALL:+VERS-TLS1.2:-KX-ALL:+PSK \
                    --pskpasswd=$PROGRAMS_DIR/mini_client.psk" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "Version: TLS1.2" \
            -S "Error" \
            -C "error"

# No TLS 1.3 PSK test cases for mini_client: it isn't supported.

requires_certificate_authentication
run_test    "Sample: mini_client, ssl_server2, certificate" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server2" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

# We don't test mini_client against ssl_server because their
# application protocol is too incompatible, which causes the client
# to error out.

requires_protocol_version tls12
requires_certificate_authentication
run_test    "Sample: mini_client, openssl server, TLS 1.2 certificate" \
            -P 4433 \
            "$O_SRV -tls1_2" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "GET / HTTP/1.0" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls12
requires_certificate_authentication
run_test    "Sample: mini_client, gnutls server, TLS 1.2 certificate" \
            -P 4433 \
            "$G_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "Version: TLS1.2" \
            -S "Error" \
            -C "error"

requires_protocol_version tls13
requires_openssl_tls1_3
requires_certificate_authentication
run_test    "Sample: mini_client, openssl server, TLS 1.3 certificate" \
            -P 4433 \
            "$O_NEXT_SRV -tls1_3" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "GET / HTTP/1.0" \
            -S "ERROR" \
            -C "error"

requires_protocol_version tls13
requires_gnutls_tls1_3
requires_certificate_authentication
run_test    "Sample: mini_client, gnutls server, TLS 1.3 certificate" \
            -P 4433 \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3" \
            "$PROGRAMS_DIR/mini_client" \
            0 \
            -s "Version: TLS1.3" \
            -S "Error" \
            -C "error"

run_test    "Sample: ssl_server, ssl_client2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$PROGRAMS_DIR/ssl_client2" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

run_test    "Sample: ssl_client1 with ssl_server" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
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
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
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
requires_gnutls_tls1_3
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$G_NEXT_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
requires_openssl_tls1_3
requires_certificate_authentication
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_server, openssl client, TLS 1.3, no middlebox compatibility" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$O_NEXT_CLI -tls1_3 -no_middlebox" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "New, TLSv1.3, Cipher is" \
            -S "error" \
            -C "ERROR"

requires_protocol_version tls13
requires_gnutls_tls1_3
requires_certificate_authentication
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_server, gnutls client, TLS 1.3, no middlebox compatibility" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_server" \
            "$G_NEXT_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

run_test    "Sample: ssl_fork_server, ssl_client2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$PROGRAMS_DIR/ssl_client2" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

run_test    "Sample: ssl_client1 with ssl_fork_server" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

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
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
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
requires_gnutls_tls1_3
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_fork_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_fork_server" \
            "$G_NEXT_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

run_test    "Sample: ssl_pthread_server, ssl_client2" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$PROGRAMS_DIR/ssl_client2" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

run_test    "Sample: ssl_client1 with ssl_pthread_server" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$PROGRAMS_DIR/ssl_client1" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -S "error" \
            -C "error"

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
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
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
requires_gnutls_tls1_3
requires_certificate_authentication
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "Sample: ssl_pthread_server, gnutls client, TLS 1.3" \
            -P 4433 \
            "$PROGRAMS_DIR/ssl_pthread_server" \
            "$G_NEXT_CLI --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3 localhost" \
            0 \
            -s "Successful connection using: TLS1-3-" \
            -c "Description:.*TLS1.3" \
            -S "error" \
            -C "ERROR"

# The server complains of extra data after it closes the connection
# because the client keeps sending data, so the server receives
# more application data when it expects a new handshake. We consider
# the test a success if both sides have sent and received application
# data, no matter what happens afterwards.
run_test    "Sample: dtls_client with dtls_server" \
            -P 4433 \
            "$PROGRAMS_DIR/dtls_server" \
            "$PROGRAMS_DIR/dtls_client" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -C "error"

# The server complains of extra data after it closes the connection
# because the client keeps sending data, so the server receives
# more application data when it expects a new handshake. We consider
# the test a success if both sides have sent and received application
# data, no matter what happens afterwards.
run_test    "Sample: ssl_client2, dtls_server" \
            -P 4433 \
            "$PROGRAMS_DIR/dtls_server" \
            "$PROGRAMS_DIR/ssl_client2 dtls=1" \
            0 \
            -s "[1-9][0-9]* bytes read" \
            -s "[1-9][0-9]* bytes written" \
            -c "[1-9][0-9]* bytes read" \
            -c "[1-9][0-9]* bytes written" \
            -C "error"

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
