#include <stdio.h>
#include <string.h>

#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <unordered_map>
#include <vector>

#include <modsecurity/modsecurity.h>
#include "transaction_clean.h"

/**
 * @name    msc_new_transaction
 * @brief   Create a new transaction for a given configuration and ModSecurity core.
 *
 * The transaction is the unit that will be used the inspect every request. It holds
 * all the information for a given request.
 * 
 * @note Remember to cleanup the transaction when the transaction is complete.
 *
 * @param ms ModSecurity core pointer.
 * @param rules Rules pointer.
 *
 * @return Pointer to Transaction structure
 * @retval >0   Transaction structure was initialized correctly
 * @retval NULL Transaction cannot be initialized, either by problems with the rules,
 *              problems with the ModSecurity core or missing memory to
 *              allocate the resources needed by the transaction.
 *
 */
extern "C" Transaction *msc_new_transaction(ModSecurity *ms,
    RulesSet *rules, void *logCbData) {
    return new Transaction(ms, rules, logCbData);
}
extern "C" Transaction *msc_new_transaction_with_id(ModSecurity *ms,
    RulesSet *rules, const char *id, void *logCbData) {
    return new Transaction(ms, rules, id, logCbData);
}


/**
 * @name    msc_process_connection
 * @brief   Perform the analysis on the connection.
 *
 * This function should be called at very beginning of a request process, it is
 * expected to be executed prior to the virtual host resolution, when the
 * connection arrives on the server.
 *
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 * @param client Client's IP address in text format.
 * @param cPort Client's port
 * @param server Server's IP address in text format.
 * @param sPort Server's port
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_connection(Transaction *transaction,
    const char *client, int cPort, const char *server, int sPort) {
    return transaction->processConnection(client, cPort, server, sPort);
}


/**
 * @name    msc_process_uri
 * @brief   Perform the analysis on the URI and all the query string variables.
 *
 * This function should be called at very beginning of a request process, it is
 * expected to be executed prior to the virtual host resolution, when the
 * connection arrives on the server.
 *
 * @note There is no direct connection between this function and any phase of
 *       the SecLanguage's phases. It is something that may occur between the
 *       SecLanguage phase 1 and 2.
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 * @param uri   Uri.
 * @param protocol   Protocol (GET, POST, PUT).
 * @param http_version   Http version (1.0, 1.2, 2.0).
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_uri(Transaction *transaction, const char *uri,
    const char *protocol, const char *http_version) {
    return transaction->processURI(uri, protocol, http_version);
}


/**
 * @name    msc_process_request_headers
 * @brief   Perform the analysis on the request readers.
 *
 * This function perform the analysis on the request headers, notice however
 * that the headers should be added prior to the execution of this function.
 *
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_request_headers(Transaction *transaction) {
    return transaction->processRequestHeaders();
}


/**
 * @name    msc_process_request_body
 * @brief   Perform the analysis on the request body (if any)
 *
 * This function perform the analysis on the request body. It is optional to
 * call that function. If this API consumer already know that there isn't a
 * body for inspect it is recommended to skip this step.
 *
 * @note It is necessary to "append" the request body prior to the execution
 *       of this function.
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 * 
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_request_body(Transaction *transaction) {
    return transaction->processRequestBody();
}


/**
 * @name    msc_append_request_body
 * @brief   Adds request body to be inspected.
 *
 * With this function it is possible to feed ModSecurity with data for
 * inspection regarding the request body. There are two possibilities here:
 * 
 * 1 - Adds the buffer in a row;
 * 2 - Adds it in chunks;
 *
 * A third option should be developed which is share your application buffer.
 * In any case, remember that the utilization of this function may reduce your
 * server throughput, as this buffer creations is computationally expensive.
 *
 * @note While feeding ModSecurity remember to keep checking if there is an
 *       intervention, Sec Language has the capability to set the maximum
 *       inspection size which may be reached, and the decision on what to do
 *       in this case is upon the rules.
 *
 * @param transaction ModSecurity transaction.
 * 
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_append_request_body(Transaction *transaction,
    const unsigned char *buf, size_t len) {
    return transaction->appendRequestBody(buf, len);
}


extern "C" int msc_request_body_from_file(Transaction *transaction,
    const char *path) {
    return transaction->requestBodyFromFile(path);
}


/**
 * @name    msc_process_response_headers
 * @brief   Perform the analysis on the response headers.
 *
 * This function perform the analysis on the response headers, notice however
 * that the headers should be added prior to the execution of this function.
 *
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_response_headers(Transaction *transaction,
    int code, const char* protocol) {
    return transaction->processResponseHeaders(code, protocol);
}


/**
 * @name    msc_process_response_body
 * @brief   Perform the analysis on the response body (if any)
 *
 * This function perform the analysis on the response body. It is optional to
 * call that function. If this API consumer already know that there isn't a
 * body for inspect it is recommended to skip this step.
 *
 * @note It is necessary to "append" the response body prior to the execution
 *       of this function.
 * @note Remember to check for a possible intervention.
 *
 * @param transaction ModSecurity transaction.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_process_response_body(Transaction *transaction) {
    return transaction->processResponseBody();
}


/**
 * @name    msc_append_response_body
 * @brief   Adds reponse body to be inspected.
 *
 * With this function it is possible to feed ModSecurity with data for
 * inspection regarding the response body. ModSecurity can also update the
 * contents of the response body, this is not quite ready yet on this version
 * of the API. 
 *
 * @note If the content is updated, the client cannot receive the content
 *       length header filled, at least not with the old values. Otherwise
 *       unexpected behavior may happens.
 *
 * @param transaction ModSecurity transaction.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_append_response_body(Transaction *transaction,
    const unsigned char *buf, size_t len) {
    return transaction->appendResponseBody(buf, len);
}


/**
 * @name    msc_add_request_header
 * @brief   Adds a request header
 *
 * With this function it is possible to feed ModSecurity with a request header.
 *
 * @note This function expects a NULL terminated string, for both: key and
 *       value.
 *
 * @param transaction ModSecurity transaction.
 * @param key   header name.
 * @param value header value.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_add_request_header(Transaction *transaction,
    const unsigned char *key,
    const unsigned char *value) {
    return transaction->addRequestHeader(key, value);
}


/**
 * @name    msc_add_n_request_header
 * @brief   Adds a request header
 *
 * Same as msc_add_request_header, do not expect a NULL terminated string,
 * instead it expect the string and the string size, for the value and key.
 *
 * @param transaction   ModSecurity transaction.
 * @param key     header name.
 * @param key_len header name size.
 * @param value   header value.
 * @param val_len header value size.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_add_n_request_header(Transaction *transaction,
    const unsigned char *key,
    size_t key_len, const unsigned char *value, size_t value_len) {
    return transaction->addRequestHeader(key, key_len, value, value_len);
}


/**
 * @name    msc_add_response_header
 * @brief   Adds a response header
 *
 * With this function it is possible to feed ModSecurity with a response
 * header.
 *
 * @note This function expects a NULL terminated string, for both: key and
 *       value.
 *
 * @param transaction   ModSecurity transaction.
 * @param key     header name.
 * @param value   header value.
 *
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_add_response_header(Transaction *transaction,
    const unsigned char *key,
    const unsigned char *value) {
    return transaction->addResponseHeader(key, value);
}


/**
 * @name    msc_add_n_response_header
 * @brief   Adds a response header
 *
 * Same as msc_add_response_header, do not expect a NULL terminated string,
 * instead it expect the string and the string size, for the value and key.
 *
 * @param transaction   ModSecurity transaction.
 * @param key     header name.
 * @param key_len header name size.
 * @param value   header value.
 * @param val_len header value size.
 * 
 * @returns If the operation was successful or not.
 * @retval 1 Operation was successful.
 * @retval 0 Operation failed.
 *
 */
extern "C" int msc_add_n_response_header(Transaction *transaction,
    const unsigned char *key, size_t key_len, const unsigned char *value,
    size_t value_len) {
    return transaction->addResponseHeader(key, key_len, value, value_len);
}


/**
 * @name    msc_get_response_body
 * @brief   Retrieve a buffer with the updated response body.
 *
 * This function is needed to be called whenever ModSecurity update the
 * contents of the response body, otherwise there is no need to call this
 * function.
 *
 * @param transaction ModSecurity transaction.
 *
 * @return It returns a buffer (const char *)
 * @retval >0   body was update and available.
 * @retval NULL Nothing was updated.
 *
 */
extern "C" const char *msc_get_response_body(const Transaction *transaction) {
    return transaction->getResponseBody();
}


/**
 * @name    msc_get_response_body_length
 * @brief   Retrieve the length of the response body.
 *
 * This function returns the size of the response body buffer.
 *
 * @param transaction ModSecurity transaction.
 *
 * @return Size of the response body.
 *
 */
extern "C" size_t msc_get_response_body_length(Transaction *transaction) {
    return transaction->getResponseBodyLength();
}

/**
 * @name    msc_get_request_body_length
 * @brief   Retrieve the length of the request body.
 *
 * This function returns the size of the request body buffer.
 *
 * @param transaction ModSecurity transaction.
 *
 * @return Size of the request body.
 *
 */
extern "C" size_t msc_get_request_body_length(Transaction *transaction) {
    return transaction->getRequestBodyLength();
}

