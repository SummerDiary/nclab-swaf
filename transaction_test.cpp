#include <iostream>
#include <cstring>
#include "transaction_clean.h"
#include "rules_set.h"
#include "modsecurity.h"

int main() {
    // Initialize ModSecurity and ruleset
    auto modsec = new ModSecurity();
    auto rules = new RulesSet();

    // Create transaction
    auto tx = msc_new_transaction(modsec, rules, nullptr);

    // Process connection
    msc_process_connection(tx, "127.0.0.1", 12345, "127.0.0.1", 80);

    // Process URI
    msc_process_uri(tx, "/index.html", "http", "1.1");

    // Add headers
    msc_add_request_header(tx, (const unsigned char*)"Host", (const unsigned char*)"localhost");
    msc_add_request_header(tx, (const unsigned char*)"User-Agent", (const unsigned char*)"TestAgent/1.0");
    msc_process_request_headers(tx);

    // Process and append body
    msc_process_request_body(tx);
    const char *body = "field1=value1&field2=value2";
    msc_append_request_body(tx, (const unsigned char*)body, std::strlen(body));

    // Inspect body length
    std::size_t len = msc_get_request_body_length(tx);
    std::cout << "Request body length: " << len << " bytes\n";

    // Clean up
    delete tx;
    delete rules;
    delete modsec;

    return 0;
}

/*
Compilation example:
  g++ -std=c++11 -I/path/to/modsecurity/include \
      transaction.cc transaction_test.cpp \
      -L/path/to/modsecurity/lib -lmodsecurity -o transaction_test
Running:
  ./transaction_test
*/

