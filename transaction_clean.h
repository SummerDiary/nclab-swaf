/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */
#include <modsecurity/modsecurity.h>

#ifndef HEADERS_MODSECURITY_TRANSACTION_H_
#define HEADERS_MODSECURITY_TRANSACTION_H_

#ifdef __cplusplus
#include <cassert>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <memory>
#include <stack>
#endif

#include <stdlib.h>
#include <stddef.h>

#ifndef __cplusplus
typedef struct ModSecurity_t ModSecurity;
typedef struct Transaction_t Transaction;
typedef struct Rules_t RulesSet;
#endif

#ifdef __cplusplus

namespace modsecurity {

class ModSecurity;
class Transaction;

#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup ModSecurity_C_API */
Transaction *msc_new_transaction(ModSecurity *ms,
    RulesSet *rules, void *logCbData);

/** @ingroup ModSecurity_C_API */
Transaction *msc_new_transaction_with_id(ModSecurity *ms,
    RulesSet *rules, const char *id, void *logCbData);

/** @ingroup ModSecurity_C_API */
int msc_process_connection(Transaction *transaction,
    const char *client, int cPort, const char *server, int sPort);

/** @ingroup ModSecurity_C_API */
int msc_process_request_headers(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_add_request_header(Transaction *transaction, const unsigned char *key,
    const unsigned char *value);

/** @ingroup ModSecurity_C_API */
int msc_add_n_request_header(Transaction *transaction,
    const unsigned char *key, size_t len_key, const unsigned char *value,
    size_t len_value);

/** @ingroup ModSecurity_C_API */
int msc_process_request_body(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_append_request_body(Transaction *transaction,
    const unsigned char *body, size_t size);

/** @ingroup ModSecurity_C_API */
int msc_request_body_from_file(Transaction *transaction, const char *path);

/** @ingroup ModSecurity_C_API */
int msc_process_response_headers(Transaction *transaction, int code,
    const char* protocol);

/** @ingroup ModSecurity_C_API */
int msc_add_response_header(Transaction *transaction,
    const unsigned char *key, const unsigned char *value);

/** @ingroup ModSecurity_C_API */
int msc_add_n_response_header(Transaction *transaction,
    const unsigned char *key, size_t len_key, const unsigned char *value,
    size_t len_value);

/** @ingroup ModSecurity_C_API */
int msc_process_response_body(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_append_response_body(Transaction *transaction,
    const unsigned char *body, size_t size);

/** @ingroup ModSecurity_C_API */
int msc_process_uri(Transaction *transaction, const char *uri,
    const char *protocol, const char *http_version);

/** @ingroup ModSecurity_C_API */
const char *msc_get_response_body(const Transaction *transaction);

/** @ingroup ModSecurity_C_API */
size_t msc_get_response_body_length(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
size_t msc_get_request_body_length(Transaction *transaction);

#ifdef __cplusplus
}
}  // namespace modsecurity
#endif


#endif  // HEADERS_MODSECURITY_TRANSACTION_H_
