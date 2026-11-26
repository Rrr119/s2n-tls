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

#include "utils/s2n_diagnostics.h"

#include <stdio.h>
#include <string.h>

#include "error/s2n_errno.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

const char *s2n_diagnostic_level_name(s2n_diagnostic_level level)
{
    switch (level) {
        case S2N_DIAGNOSTIC_LEVEL_NONE:
            return "none";
        case S2N_DIAGNOSTIC_LEVEL_DEBUG:
            return "debug";
        case S2N_DIAGNOSTIC_LEVEL_INFO:
            return "info";
        case S2N_DIAGNOSTIC_LEVEL_WARNING:
            return "warning";
        case S2N_DIAGNOSTIC_LEVEL_ERROR:
            return "error";
    }
    return "unknown";
}

const char *s2n_handshake_diagnostic_level_name(s2n_handshake_diagnostic_level level)
{
    return s2n_diagnostic_level_name(level);
}

const char *s2n_handshake_stage_name(s2n_handshake_stage stage)
{
    switch (stage) {
        case S2N_HANDSHAKE_STAGE_UNKNOWN:
            return "unknown";
        case S2N_HANDSHAKE_STAGE_INIT:
            return "init";
        case S2N_HANDSHAKE_STAGE_CLIENT_HELLO:
            return "client_hello";
        case S2N_HANDSHAKE_STAGE_SERVER_HELLO:
            return "server_hello";
        case S2N_HANDSHAKE_STAGE_HELLO_RETRY:
            return "hello_retry";
        case S2N_HANDSHAKE_STAGE_ENCRYPTED_EXTENSIONS:
            return "encrypted_extensions";
        case S2N_HANDSHAKE_STAGE_CERTIFICATE_REQUEST:
            return "certificate_request";
        case S2N_HANDSHAKE_STAGE_CERTIFICATE:
            return "certificate";
        case S2N_HANDSHAKE_STAGE_CERTIFICATE_VERIFY:
            return "certificate_verify";
        case S2N_HANDSHAKE_STAGE_KEY_EXCHANGE:
            return "key_exchange";
        case S2N_HANDSHAKE_STAGE_FINISHED:
            return "finished";
        case S2N_HANDSHAKE_STAGE_COMPLETE:
            return "complete";
    }
    return "unknown";
}

const char *s2n_handshake_failure_category_name(s2n_handshake_failure_category category)
{
    switch (category) {
        case S2N_HANDSHAKE_FAILURE_NONE:
            return "none";
        case S2N_HANDSHAKE_FAILURE_CERTIFICATE:
            return "certificate";
        case S2N_HANDSHAKE_FAILURE_ALGORITHM:
            return "algorithm";
        case S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION:
            return "protocol_version";
        case S2N_HANDSHAKE_FAILURE_IO:
            return "io";
        case S2N_HANDSHAKE_FAILURE_CLOSED:
            return "closed";
        case S2N_HANDSHAKE_FAILURE_BLOCKED:
            return "blocked";
        case S2N_HANDSHAKE_FAILURE_PEER_ALERT:
            return "peer_alert";
        case S2N_HANDSHAKE_FAILURE_PROTOCOL:
            return "protocol";
        case S2N_HANDSHAKE_FAILURE_INTERNAL:
            return "internal";
        case S2N_HANDSHAKE_FAILURE_USAGE:
            return "usage";
        case S2N_HANDSHAKE_FAILURE_UNKNOWN:
            break;
    }
    return "unknown";
}

const char *s2n_handshake_failure_type_name(s2n_handshake_failure_type type)
{
    return s2n_handshake_failure_category_name(type);
}

const char *s2n_failure_category_name(s2n_failure_category category)
{
    return s2n_handshake_failure_category_name(category);
}

const char *s2n_failure_type_name(s2n_failure_type type)
{
    return s2n_handshake_failure_category_name(type);
}

const char *s2n_handshake_failure_category_string(s2n_handshake_failure_category category)
{
    return s2n_handshake_failure_category_name(category);
}

static bool s2n_error_is_certificate_failure(int error_code)
{
    switch (error_code) {
        case S2N_ERR_UNEXPECTED_CERT_REQUEST:
        case S2N_ERR_MISSING_CERT_REQUEST:
        case S2N_ERR_MISSING_CLIENT_CERT:
        case S2N_ERR_DECODE_CERTIFICATE:
        case S2N_ERR_DECODE_PRIVATE_KEY:
        case S2N_ERR_CERT_UNTRUSTED:
        case S2N_ERR_CERT_INVALID_HOSTNAME:
        case S2N_ERR_CERT_REVOKED:
        case S2N_ERR_CERT_NOT_YET_VALID:
        case S2N_ERR_CERT_EXPIRED:
        case S2N_ERR_CERT_TYPE_UNSUPPORTED:
        case S2N_ERR_CERT_INVALID:
        case S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED:
        case S2N_ERR_CERT_REJECTED:
        case S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION:
        case S2N_ERR_CRL_LOOKUP_FAILED:
        case S2N_ERR_CRL_SIGNATURE:
        case S2N_ERR_CRL_ISSUER:
        case S2N_ERR_CRL_UNHANDLED_CRITICAL_EXTENSION:
        case S2N_ERR_CRL_INVALID_THIS_UPDATE:
        case S2N_ERR_CRL_INVALID_NEXT_UPDATE:
        case S2N_ERR_CRL_NOT_YET_VALID:
        case S2N_ERR_CRL_EXPIRED:
        case S2N_ERR_X509_TRUST_STORE:
        case S2N_ERR_NULL_CN_NAME:
        case S2N_ERR_NULL_SANS:
        case S2N_ERR_INVALID_OCSP_RESPONSE:
        case S2N_ERR_NO_CERT_FOUND:
        case S2N_ERR_CERT_NOT_VALIDATED:
        case S2N_ERR_NO_PRIVATE_KEY:
        case S2N_ERR_CERT_OWNERSHIP:
        case S2N_ERR_INVALID_CERT_STATE:
        case S2N_ERR_KEY_MISMATCH:
        case S2N_ERR_NO_CERTIFICATE_IN_PEM:
        case S2N_ERR_TOO_MANY_CERTIFICATES:
        case S2N_ERR_TOO_MANY_CAS:
            return true;
        default:
            return false;
    }
}

static bool s2n_error_is_algorithm_failure(int error_code)
{
    switch (error_code) {
        case S2N_ERR_KEY_INIT:
        case S2N_ERR_CIPHER_NOT_SUPPORTED:
        case S2N_ERR_HASH_INVALID_ALGORITHM:
        case S2N_ERR_PRF_INVALID_ALGORITHM:
        case S2N_ERR_P_HASH_INVALID_ALGORITHM:
        case S2N_ERR_INVALID_SIGNATURE_ALGORITHM:
        case S2N_ERR_INVALID_SIGNATURE_SCHEME:
        case S2N_ERR_NO_VALID_SIGNATURE_SCHEME:
        case S2N_ERR_ECDHE_UNSUPPORTED_CURVE:
        case S2N_ERR_ECDSA_UNSUPPORTED_CURVE:
        case S2N_ERR_KEM_UNSUPPORTED_PARAMS:
        case S2N_ERR_HMAC_INVALID_ALGORITHM:
        case S2N_ERR_INVALID_NONCE_TYPE:
        case S2N_ERR_CIPHER_TYPE:
        case S2N_ERR_INVALID_CIPHER_PREFERENCES:
        case S2N_ERR_RSA_PSS_NOT_SUPPORTED:
        case S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES:
        case S2N_ERR_INVALID_ECC_PREFERENCES:
        case S2N_ERR_INVALID_KEM_PREFERENCES:
        case S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT:
        case S2N_ERR_API_UNSUPPORTED_BY_LIBCRYPTO:
        case S2N_ERR_PQ_CRYPTO:
            return true;
        default:
            return false;
    }
}

static bool s2n_error_is_protocol_version_failure(int error_code)
{
    switch (error_code) {
        case S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED:
        case S2N_ERR_UNKNOWN_PROTOCOL_VERSION:
        case S2N_ERR_CLIENT_HELLO_VERSION:
        case S2N_ERR_CLIENT_PROTOCOL_VERSION:
        case S2N_ERR_SERVER_PROTOCOL_VERSION:
        case S2N_ERR_ACTUAL_PROTOCOL_VERSION:
            return true;
        default:
            return false;
    }
}

static s2n_handshake_failure_category s2n_alert_get_failure_category(int alert_code)
{
    switch (alert_code) {
        case S2N_TLS_ALERT_BAD_CERTIFICATE:
        case S2N_TLS_ALERT_UNSUPPORTED_CERTIFICATE:
        case S2N_TLS_ALERT_CERTIFICATE_REVOKED:
        case S2N_TLS_ALERT_CERTIFICATE_EXPIRED:
        case S2N_TLS_ALERT_CERTIFICATE_UNKNOWN:
        case S2N_TLS_ALERT_UNKNOWN_CA:
        case S2N_TLS_ALERT_ACCESS_DENIED:
        case S2N_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE:
        case S2N_TLS_ALERT_CERTIFICATE_REQUIRED:
            return S2N_HANDSHAKE_FAILURE_CERTIFICATE;
        case S2N_TLS_ALERT_INSUFFICIENT_SECURITY:
            return S2N_HANDSHAKE_FAILURE_ALGORITHM;
        case S2N_TLS_ALERT_PROTOCOL_VERSION:
            return S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION;
        default:
            return S2N_HANDSHAKE_FAILURE_UNKNOWN;
    }
}

s2n_handshake_failure_category s2n_handshake_diagnostic_classify(int error_code, int alert_code)
{
    if (error_code == S2N_ERR_OK) {
        return S2N_HANDSHAKE_FAILURE_NONE;
    }

    s2n_handshake_failure_category alert_category = s2n_alert_get_failure_category(alert_code);
    if (alert_category != S2N_HANDSHAKE_FAILURE_UNKNOWN) {
        return alert_category;
    }

    if (s2n_error_is_certificate_failure(error_code)) {
        return S2N_HANDSHAKE_FAILURE_CERTIFICATE;
    }
    if (s2n_error_is_algorithm_failure(error_code)) {
        return S2N_HANDSHAKE_FAILURE_ALGORITHM;
    }
    if (s2n_error_is_protocol_version_failure(error_code)) {
        return S2N_HANDSHAKE_FAILURE_PROTOCOL_VERSION;
    }

    if (s2n_error_get_type(error_code) == S2N_ERR_T_ALERT) {
        return S2N_HANDSHAKE_FAILURE_PEER_ALERT;
    }

    switch (s2n_error_get_type(error_code)) {
        case S2N_ERR_T_OK:
            return S2N_HANDSHAKE_FAILURE_NONE;
        case S2N_ERR_T_IO:
            return S2N_HANDSHAKE_FAILURE_IO;
        case S2N_ERR_T_CLOSED:
            return S2N_HANDSHAKE_FAILURE_CLOSED;
        case S2N_ERR_T_BLOCKED:
            return S2N_HANDSHAKE_FAILURE_BLOCKED;
        case S2N_ERR_T_PROTO:
            return S2N_HANDSHAKE_FAILURE_PROTOCOL;
        case S2N_ERR_T_INTERNAL:
            return S2N_HANDSHAKE_FAILURE_INTERNAL;
        case S2N_ERR_T_USAGE:
            return S2N_HANDSHAKE_FAILURE_USAGE;
        case S2N_ERR_T_ALERT:
            return S2N_HANDSHAKE_FAILURE_PEER_ALERT;
    }

    return S2N_HANDSHAKE_FAILURE_UNKNOWN;
}

s2n_handshake_failure_category s2n_error_get_handshake_failure_category(int error_code)
{
    return s2n_handshake_diagnostic_classify(error_code, -1);
}

s2n_handshake_failure_type s2n_error_get_handshake_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_category s2n_error_get_failure_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_type s2n_error_get_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_category s2n_classify_handshake_error(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_category s2n_handshake_classify_error(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_type s2n_error_to_handshake_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_type s2n_error_code_to_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_category s2n_get_handshake_failure_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_type s2n_get_handshake_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_error_category s2n_get_error_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_category s2n_handshake_diagnostics_classify(int error_code, int alert_code)
{
    return s2n_handshake_diagnostic_classify(error_code, alert_code);
}

s2n_handshake_failure_category s2n_diagnose_handshake_error(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_error_category s2n_get_handshake_error_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_error_category s2n_error_get_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_failure_category s2n_get_failure_category(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_failure_type s2n_get_failure_type(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_failure_type s2n_handshake_failure_type_from_error(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_failure_type s2n_failure_type_from_error(int error_code)
{
    return s2n_error_get_handshake_failure_category(error_code);
}

s2n_handshake_stage s2n_diagnostics_stage_from_name(const char *checkpoint_name)
{
    if (checkpoint_name == NULL) {
        return S2N_HANDSHAKE_STAGE_UNKNOWN;
    }

    if (strcmp(checkpoint_name, "NEGOTIATE_START") == 0) {
        return S2N_HANDSHAKE_STAGE_INIT;
    }
    if (strcmp(checkpoint_name, "NEGOTIATE_END") == 0) {
        return S2N_HANDSHAKE_STAGE_COMPLETE;
    }
    if (strcmp(checkpoint_name, "CLIENT_HELLO") == 0) {
        return S2N_HANDSHAKE_STAGE_CLIENT_HELLO;
    }
    if (strcmp(checkpoint_name, "SERVER_HELLO") == 0) {
        return S2N_HANDSHAKE_STAGE_SERVER_HELLO;
    }
    if (strcmp(checkpoint_name, "HELLO_RETRY_MSG") == 0) {
        return S2N_HANDSHAKE_STAGE_HELLO_RETRY;
    }
    if (strcmp(checkpoint_name, "ENCRYPTED_EXTENSIONS") == 0) {
        return S2N_HANDSHAKE_STAGE_ENCRYPTED_EXTENSIONS;
    }
    if (strcmp(checkpoint_name, "SERVER_CERT_REQ") == 0) {
        return S2N_HANDSHAKE_STAGE_CERTIFICATE_REQUEST;
    }
    if (strcmp(checkpoint_name, "SERVER_CERT") == 0 || strcmp(checkpoint_name, "CLIENT_CERT") == 0
            || strcmp(checkpoint_name, "SERVER_CERT_STATUS") == 0) {
        return S2N_HANDSHAKE_STAGE_CERTIFICATE;
    }
    if (strcmp(checkpoint_name, "SERVER_CERT_VERIFY") == 0
            || strcmp(checkpoint_name, "CLIENT_CERT_VERIFY") == 0) {
        return S2N_HANDSHAKE_STAGE_CERTIFICATE_VERIFY;
    }
    if (strcmp(checkpoint_name, "SERVER_KEY") == 0 || strcmp(checkpoint_name, "CLIENT_KEY") == 0
            || strcmp(checkpoint_name, "CLIENT_CHANGE_CIPHER_SPEC") == 0
            || strcmp(checkpoint_name, "SERVER_CHANGE_CIPHER_SPEC") == 0) {
        return S2N_HANDSHAKE_STAGE_KEY_EXCHANGE;
    }
    if (strcmp(checkpoint_name, "CLIENT_FINISHED") == 0 || strcmp(checkpoint_name, "SERVER_FINISHED") == 0) {
        return S2N_HANDSHAKE_STAGE_FINISHED;
    }
    if (strcmp(checkpoint_name, "APPLICATION_DATA") == 0) {
        return S2N_HANDSHAKE_STAGE_COMPLETE;
    }

    return S2N_HANDSHAKE_STAGE_UNKNOWN;
}

static bool s2n_diagnostics_is_noisy_record_checkpoint(const char *name)
{
    return name != NULL
            && (strcmp(name, "RECORD_READ") == 0 || strcmp(name, "RECORD_WRITE") == 0);
}

static bool s2n_diagnostics_callback_enabled(const struct s2n_connection *conn)
{
    if (conn->diagnostic_callback != NULL) {
        return true;
    }
    if (conn->config != NULL
            && (conn->config->on_handshake_diagnostic != NULL
                    || conn->config->on_handshake_diagnostic_simple != NULL)) {
        return true;
    }
    return false;
}

static int s2n_diagnostics_safe_alert(struct s2n_connection *conn)
{
    int saved_errno = s2n_errno;
    struct s2n_debug_info saved_debug = _s2n_debug_info;
    int alert_code = s2n_connection_get_alert(conn);
    if (alert_code < 0) {
        alert_code = -1;
    }
    s2n_errno = saved_errno;
    _s2n_debug_info = saved_debug;
    return alert_code;
}

static void s2n_diagnostics_populate(
        struct s2n_connection *conn,
        s2n_handshake_diagnostic_level level,
        s2n_handshake_stage stage,
        int error_code,
        struct s2n_handshake_diagnostic_event *diagnostic)
{
    if (diagnostic == NULL) {
        return;
    }

    int alert_code = -1;
    if (conn != NULL) {
        alert_code = s2n_diagnostics_safe_alert(conn);
    }

    uint64_t timestamp_ns = 0;
    if (s2n_default_monotonic_clock(NULL, &timestamp_ns) != S2N_SUCCESS) {
        timestamp_ns = 0;
    }

    if (stage == S2N_HANDSHAKE_STAGE_UNKNOWN && conn != NULL
            && s2n_result_is_ok(s2n_handshake_validate(&(conn->handshake)))) {
        stage = s2n_diagnostics_stage_from_name(
                s2n_connection_get_last_message_name(conn));
    }

    s2n_handshake_failure_category category = s2n_handshake_diagnostic_classify(error_code, alert_code);
    const char *level_name = s2n_handshake_diagnostic_level_name(level);
    const char *stage_name = s2n_handshake_stage_name(stage);
    const char *category_name = s2n_handshake_failure_category_name(category);
    const char *error_name = error_code == S2N_ERR_OK ? "S2N_ERR_OK" : s2n_strerror_name(error_code);
    const char *error_message = error_code == S2N_ERR_OK ? "no error" : s2n_strerror(error_code, "EN");
    const char *source = NULL;
    if (error_code != S2N_ERR_OK && _s2n_debug_info.source != NULL && _s2n_debug_info.source[0] != '\0') {
        source = _s2n_debug_info.source;
    }

    *diagnostic = (struct s2n_handshake_diagnostic_event) {
        .size = sizeof(*diagnostic),
        .abi_version = S2N_HANDSHAKE_DIAGNOSTIC_ABI_VERSION,
        .timestamp_ns = timestamp_ns,
        .level = level,
        .severity = level,
        .diagnostic_level = level,
        .stage = stage,
        .handshake_stage = stage,
        .category = category,
        .failure_category = category,
        .failure_type = category,
        .classification = category,
        .error_code = error_code,
        .code = error_code,
        .error = error_code,
        .s2n_error = error_code,
        .s2n_error_code = error_code,
        .error_type = s2n_error_get_type(error_code),
        .alert_code = alert_code,
        .alert = alert_code,
        .tls_alert = alert_code,
        .protocol_version = conn == NULL ? S2N_UNKNOWN_PROTOCOL_VERSION : conn->actual_protocol_version,
        .level_name = level_name,
        .severity_name = level_name,
        .stage_name = stage_name,
        .category_name = category_name,
        .failure_type_name = category_name,
        .error_name = error_name,
        .error_message = error_message,
        .message = error_message,
        .diagnostic_message = error_message,
        .description = error_message,
        .source = source,
        .timestamp = timestamp_ns,
    };
}

static S2N_RESULT s2n_diagnostics_send(
        struct s2n_connection *conn,
        struct s2n_handshake_diagnostic_event *diagnostic)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(diagnostic);

    if (conn->diagnostic_callback_set && conn->diagnostic_callback != NULL) {
        conn->diagnostic_callback(conn, conn->diagnostic_ctx, diagnostic);
    }

    if (conn->config != NULL) {
        struct s2n_config *config = conn->config;
        if (config->on_handshake_diagnostic != NULL) {
            void *context = config->handshake_diagnostic_use_subscriber
                    ? config->subscriber
                    : config->handshake_diagnostic_ctx;
            config->on_handshake_diagnostic(conn, context, diagnostic);
        }

        if (config->on_handshake_diagnostic_simple != NULL) {
            config->on_handshake_diagnostic_simple(
                    diagnostic, config->handshake_diagnostic_simple_ctx);
        }
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_diagnostics_checkpoint(struct s2n_connection *conn, const char *checkpoint_name)
{
    RESULT_ENSURE_REF(conn);

    if (s2n_diagnostics_is_noisy_record_checkpoint(checkpoint_name)) {
        return S2N_RESULT_OK;
    }
    if (!s2n_diagnostics_callback_enabled(conn)) {
        return S2N_RESULT_OK;
    }

    s2n_handshake_stage stage = s2n_diagnostics_stage_from_name(checkpoint_name);
    s2n_handshake_diagnostic_level level = S2N_DIAGNOSTIC_LEVEL_DEBUG;
    if (stage == S2N_HANDSHAKE_STAGE_INIT || stage == S2N_HANDSHAKE_STAGE_COMPLETE
            || stage == S2N_HANDSHAKE_STAGE_HELLO_RETRY) {
        level = S2N_DIAGNOSTIC_LEVEL_INFO;
    }

    int saved_errno = s2n_errno;
    struct s2n_debug_info saved_debug = _s2n_debug_info;

    struct s2n_handshake_diagnostic_event diagnostic = { 0 };
    s2n_diagnostics_populate(conn, level, stage, S2N_ERR_OK, &diagnostic);
    RESULT_GUARD(s2n_diagnostics_send(conn, &diagnostic));

    s2n_errno = saved_errno;
    _s2n_debug_info = saved_debug;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_diagnostics_failure(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    int saved_errno = s2n_errno;
    struct s2n_debug_info saved_debug = _s2n_debug_info;
    struct s2n_handshake_diagnostic_event diagnostic = { 0 };

    s2n_diagnostics_populate(
            conn, S2N_DIAGNOSTIC_LEVEL_ERROR, S2N_HANDSHAKE_STAGE_UNKNOWN, saved_errno,
            &diagnostic);

    if (conn->last_diagnostic == NULL) {
        struct s2n_blob diagnostic_memory = { 0 };
        if (s2n_alloc(&diagnostic_memory, sizeof(*conn->last_diagnostic)) == S2N_SUCCESS) {
            conn->last_diagnostic = (struct s2n_handshake_diagnostic_event *) (void *)
                    diagnostic_memory.data;
        }
    }
    if (conn->last_diagnostic != NULL) {
        *conn->last_diagnostic = diagnostic;
        RESULT_GUARD(s2n_diagnostics_send(conn, conn->last_diagnostic));
    } else {
        RESULT_GUARD(s2n_diagnostics_send(conn, &diagnostic));
    }

    s2n_errno = saved_errno;
    _s2n_debug_info = saved_debug;
    return S2N_RESULT_OK;
}

int s2n_handshake_diagnostic_init_from_error(
        s2n_handshake_diagnostic_event *diagnostic,
        int error_code)
{
    POSIX_ENSURE_REF(diagnostic);

    int saved_errno = s2n_errno;
    struct s2n_debug_info saved_debug = _s2n_debug_info;
    s2n_diagnostics_populate(
            NULL, S2N_DIAGNOSTIC_LEVEL_ERROR, S2N_HANDSHAKE_STAGE_UNKNOWN, error_code, diagnostic);
    diagnostic->source = NULL;
    s2n_errno = saved_errno;
    _s2n_debug_info = saved_debug;
    return S2N_SUCCESS;
}

int s2n_handshake_diagnostic_event_describe(
        const s2n_handshake_diagnostic_event *diagnostic,
        char *output,
        size_t output_size)
{
    POSIX_ENSURE_REF(diagnostic);
    POSIX_ENSURE(output != NULL || output_size == 0, S2N_ERR_NULL);

    int written = snprintf(
            output, output_size,
            "ts=%llu level=%s stage=%s category=%s error_type=%d s2n_error=%d "
            "error_name=%s alert=%d protocol_version=%d message=\"%s\"",
            (unsigned long long) diagnostic->timestamp_ns,
            s2n_handshake_diagnostic_level_name(diagnostic->level),
            s2n_handshake_stage_name(diagnostic->stage),
            s2n_handshake_failure_category_name(diagnostic->category),
            diagnostic->error_type,
            diagnostic->error_code,
            diagnostic->error_name != NULL ? diagnostic->error_name : "unknown",
            diagnostic->alert_code,
            diagnostic->protocol_version,
            diagnostic->error_message != NULL ? diagnostic->error_message : "");
    POSIX_ENSURE(written >= 0, S2N_ERR_SAFETY);
    POSIX_ENSURE((size_t) written < output_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    return S2N_SUCCESS;
}

int s2n_config_set_handshake_diagnostic_callback(
        struct s2n_config *config,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    POSIX_ENSURE_REF(config);
    config->on_handshake_diagnostic = callback;
    config->handshake_diagnostic_ctx = context;
    config->handshake_diagnostic_use_subscriber = false;
    return S2N_SUCCESS;
}

int s2n_config_set_handshake_diagnostic_event_callback(
        struct s2n_config *config,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_handshake_diagnostics_callback(
        struct s2n_config *config,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_diagnostic_callback(
        struct s2n_config *config,
        s2n_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_handshake_diagnostic_cb(
        struct s2n_config *config,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_handshake_diagnostics_cb(
        struct s2n_config *config,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_diagnostics_cb(
        struct s2n_config *config,
        s2n_diagnostic_callback callback,
        void *context)
{
    return s2n_config_set_handshake_diagnostic_callback(config, callback, context);
}

int s2n_config_set_handshake_diagnostic_simple_callback(
        struct s2n_config *config,
        s2n_handshake_diagnostic_simple_callback callback,
        void *context)
{
    POSIX_ENSURE_REF(config);
    config->on_handshake_diagnostic_simple = callback;
    config->handshake_diagnostic_simple_ctx = context;
    return S2N_SUCCESS;
}

int s2n_config_set_diagnostic_event(struct s2n_config *config, s2n_event_on_diagnostic_cb callback)
{
    POSIX_ENSURE_REF(config);
    config->on_handshake_diagnostic = (s2n_handshake_diagnostic_callback) callback;
    config->handshake_diagnostic_ctx = NULL;
    config->handshake_diagnostic_use_subscriber = true;
    return S2N_SUCCESS;
}

int s2n_config_set_handshake_diagnostic_event(
        struct s2n_config *config,
        s2n_event_on_diagnostic_cb callback)
{
    return s2n_config_set_diagnostic_event(config, callback);
}

int s2n_connection_set_handshake_diagnostic_callback(
        struct s2n_connection *conn,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    POSIX_ENSURE_REF(conn);
    conn->diagnostic_callback = callback;
    conn->diagnostic_ctx = context;
    conn->diagnostic_callback_set = true;
    return S2N_SUCCESS;
}

int s2n_connection_set_diagnostic_callback(
        struct s2n_connection *conn,
        s2n_diagnostic_callback callback,
        void *context)
{
    return s2n_connection_set_handshake_diagnostic_callback(conn, callback, context);
}

int s2n_connection_set_handshake_diagnostic_cb(
        struct s2n_connection *conn,
        s2n_handshake_diagnostic_callback callback,
        void *context)
{
    return s2n_connection_set_handshake_diagnostic_callback(conn, callback, context);
}

const s2n_handshake_diagnostic_event *s2n_connection_get_last_handshake_diagnostic(
        struct s2n_connection *conn)
{
    if (conn == NULL || conn->last_diagnostic == NULL || conn->last_diagnostic->size == 0) {
        return NULL;
    }
    return conn->last_diagnostic;
}

const s2n_diagnostic_event *s2n_connection_get_diagnostic(struct s2n_connection *conn)
{
    return s2n_connection_get_last_handshake_diagnostic(conn);
}

s2n_handshake_failure_category s2n_connection_get_handshake_failure_category(
        struct s2n_connection *conn)
{
    if (conn == NULL) {
        return S2N_HANDSHAKE_FAILURE_UNKNOWN;
    }
    if (conn->last_diagnostic != NULL && conn->last_diagnostic->size != 0) {
        return conn->last_diagnostic->category;
    }
    return s2n_handshake_diagnostic_classify(s2n_errno, s2n_diagnostics_safe_alert(conn));
}

s2n_handshake_failure_type s2n_connection_get_handshake_failure_type(struct s2n_connection *conn)
{
    return s2n_connection_get_handshake_failure_category(conn);
}

s2n_error_category s2n_connection_get_error_category(struct s2n_connection *conn)
{
    return s2n_connection_get_handshake_failure_category(conn);
}

s2n_failure_category s2n_connection_get_failure_category(struct s2n_connection *conn)
{
    return s2n_connection_get_handshake_failure_category(conn);
}

s2n_failure_type s2n_connection_get_failure_type(struct s2n_connection *conn)
{
    return s2n_connection_get_handshake_failure_category(conn);
}
