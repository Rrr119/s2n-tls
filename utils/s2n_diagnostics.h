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

#pragma once

#include "api/s2n.h"
#include "utils/s2n_result.h"

struct s2n_connection;

s2n_handshake_stage s2n_diagnostics_stage_from_name(const char *checkpoint_name);
S2N_RESULT s2n_diagnostics_checkpoint(struct s2n_connection *conn, const char *checkpoint_name);
S2N_RESULT s2n_diagnostics_failure(struct s2n_connection *conn);
