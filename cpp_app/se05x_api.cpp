/**
 * @file se05x_api.cpp
 * @brief Se05xClient factories - own the connection/backend/facade as one unit.
 */

#include "se05x_api.hpp"
#include "pkcs11_ctx.hpp" // Pkcs11Backend

namespace se05x {

Se05xClient::~Se05xClient() = default;

std::unique_ptr<Se05xClient> Se05xClient::openSss(const char *port, bool selectApplet) {
    std::unique_ptr<Se05xClient> c(new Se05xClient());
    c->conn_ = std::make_unique<SssConnection>(port, selectApplet);
    c->sss_ = std::make_unique<SssBackend>(c->conn_->session());
    // Same backend serves crypto and the SSS-only management ops.
    c->api_ = std::make_unique<Se05x>(*c->sss_, c->sss_.get());
    return c;
}

std::unique_ptr<Se05xClient> Se05xClient::openPkcs11(const char *libPath) {
    std::unique_ptr<Se05xClient> c(new Se05xClient());
    c->crypto_ = std::make_unique<Pkcs11Backend>(libPath);
    c->api_ = std::make_unique<Se05x>(*c->crypto_); // crypto only; management throws
    return c;
}

} // namespace se05x
