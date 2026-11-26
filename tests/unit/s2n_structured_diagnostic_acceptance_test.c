/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "api/s2n.h"

#include <string.h>

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"

struct diagnostic_capture {
    uint32_t events;
    uint32_t errors;
    s2n_handshake_diagnostic_event error_event;
};

static void capture_diagnostic(
        struct s2n_connection *conn,
        void *context,
        s2n_handshake_diagnostic_event *diagnostic)
{
    (void) conn;
    struct diagnostic_capture *capture = context;
    EXPECT_NOT_NULL(capture);
    EXPECT_NOT_NULL(diagnostic);

    capture->events++;
    if (diagnostic->level == S2N_DIAGNOSTIC_LEVEL_ERROR) {
        capture->errors++;
        capture->error_event = *diagnostic;
    }
}

static S2N_RESULT configure_diagnostic_callback(
        struct s2n_config *config,
        struct diagnostic_capture *capture)
{
    RESULT_GUARD_POSIX(s2n_config_set_handshake_diagnostic_callback(
            config, capture_diagnostic, capture));
    return S2N_RESULT_OK;
}

static void expect_safe_diagnostic(struct diagnostic_capture *capture, const char *private_key_pem)
{
    EXPECT_TRUE(capture->errors > 0);
    EXPECT_TRUE(capture->error_event.error_code != S2N_ERR_OK);
    EXPECT_NOT_NULL(capture->error_event.error_name);
    EXPECT_NOT_NULL(capture->error_event.error_message);
    EXPECT_NOT_NULL(capture->error_event.stage_name);
    EXPECT_NOT_NULL(capture->error_event.category_name);

    char described[2048] = { 0 };
    EXPECT_SUCCESS(s2n_handshake_diagnostic_event_describe(
            &capture->error_event, described, sizeof(described)));
    EXPECT_NULL(strstr(described, "PRIVATE KEY"));
    if (private_key_pem != NULL) {
        EXPECT_NULL(strstr(described, private_key_pem));
    }
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    /* Error-code mapping for the three required failure families. */
    {
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_CERT_EXPIRED),
                S2N_HANDSHAKE_FAILURE_CERTIFICATE);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_CERT_UNTRUSTED),
                S2N_HANDSHAKE_FAILURE_CERTIFICATE);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_DECODE_CERTIFICATE),
                S2N_HANDSHAKE_FAILURE_CERTIFICATE);

        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_CIPHER_NOT_SUPPORTED),
                S2N_HANDSHAKE_FAILURE_ALGORITHM);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_NO_VALID_SIGNATURE_SCHEME),
                S2N_HANDSHAKE_FAILURE_ALGORITHM);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_ECDHE_UNSUPPORTED_CURVE),
                S2N_HANDSHAKE_FAILURE_ALGORITHM);

        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED),
                S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_UNKNOWN_PROTOCOL_VERSION),
                S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);
        EXPECT_EQUAL(s2n_error_get_handshake_failure_category(S2N_ERR_CLIENT_PROTOCOL_VERSION),
                S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);

        EXPECT_EQUAL(s2n_handshake_diagnostic_classify(S2N_ERR_ALERT, S2N_TLS_ALERT_BAD_CERTIFICATE),
                S2N_HANDSHAKE_FAILURE_CERTIFICATE);
        EXPECT_EQUAL(s2n_handshake_diagnostic_classify(S2N_ERR_ALERT, S2N_TLS_ALERT_PROTOCOL_VERSION),
                S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);
        EXPECT_EQUAL(s2n_handshake_diagnostic_classify(S2N_ERR_ALERT, S2N_TLS_ALERT_INSUFFICIENT_SECURITY),
                S2N_HANDSHAKE_FAILURE_ALGORITHM);

        EXPECT_STRING_EQUAL(s2n_handshake_failure_category_name(S2N_HANDSHAKE_FAILURE_CERTIFICATE),
                "certificate");
        EXPECT_STRING_EQUAL(s2n_handshake_failure_category_name(S2N_HANDSHAKE_FAILURE_ALGORITHM),
                "algorithm");
        EXPECT_STRING_EQUAL(
                s2n_handshake_failure_category_name(S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION),
                "protocol_version");

        /* Compatibility aliases resolve to the same mapping. */
        s2n_handshake_failure_type failure_type = s2n_error_get_handshake_failure_type(
                S2N_ERR_CIPHER_NOT_SUPPORTED);
        EXPECT_EQUAL(failure_type, S2N_HANDSHAKE_FAILURE_ALGORITHM);
        EXPECT_EQUAL(s2n_error_get_failure_type(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED),
                S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);
    }

    /* Certificate failure during a real self-talk handshake. */
    {
        struct diagnostic_capture capture = { 0 };

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_OK(configure_diagnostic_callback(server_config, &capture));
        EXPECT_OK(configure_diagnostic_callback(client_config, &capture));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_set_server_name(client, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_negotiate_test_server_and_client(server, client), S2N_ERR_CERT_UNTRUSTED);

        expect_safe_diagnostic(&capture, private_key_pem);
        EXPECT_EQUAL(capture.error_event.category, S2N_HANDSHAKE_FAILURE_CERTIFICATE);
        EXPECT_EQUAL(capture.error_event.failure_type, S2N_HANDSHAKE_FAILURE_CERTIFICATE);
        EXPECT_NOT_NULL(s2n_connection_get_last_handshake_diagnostic(client));
    }

    /* Protocol-version failure during self-talk. */
    {
        struct diagnostic_capture capture = { 0 };

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_OK(configure_diagnostic_callback(server_config, &capture));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "CloudFront-TLS-1-2-2019"));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_OK(configure_diagnostic_callback(client_config, &capture));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls12"));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        client->client_protocol_version = S2N_TLS10;

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_negotiate_test_server_and_client(server, client),
                S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

        expect_safe_diagnostic(&capture, private_key_pem);
        EXPECT_EQUAL(capture.error_event.category, S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION);
    }

    /* An empty algorithm preference set fails from s2n_negotiate and maps to algorithm. */
    {
        struct diagnostic_capture capture = { 0 };

        static struct s2n_cipher_suite *empty_suites[] = { NULL };
        struct s2n_cipher_preferences empty_cipher_preferences = {
            .count = 0,
            .suites = empty_suites,
        };
        struct s2n_security_policy no_algorithm_policy = {
            .minimum_protocol_version = S2N_TLS12,
            .cipher_preferences = &empty_cipher_preferences,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20201021,
            .ecc_preferences = &s2n_ecc_preferences_test_all,
        };

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_OK(configure_diagnostic_callback(client_config, &capture));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        client->security_policy_override = &no_algorithm_policy;

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE(s2n_negotiate(client, &blocked));

        expect_safe_diagnostic(&capture, private_key_pem);
        EXPECT_EQUAL(capture.error_event.category, S2N_HANDSHAKE_FAILURE_ALGORITHM);
        EXPECT_EQUAL(s2n_connection_get_diagnostic(client)->failure_type,
                S2N_HANDSHAKE_FAILURE_ALGORITHM);
    }

    END_TEST();
}
