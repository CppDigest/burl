//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_OPTIONS_HPP
#define BOOST_BURL_OPTIONS_HPP

#include <boost/burl/fwd.hpp>
#include <boost/http/fields.hpp>

#include <chrono>
#include <optional>
#include <string>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** Tag type indicating multi-threaded execution.

    When passed to session constructor with an external io_context,
    indicates that the io_context will be run from multiple threads.
    The session will use a strand to ensure thread safety.

    @see multithreaded
*/
struct multithreaded_t
{
    explicit constexpr multithreaded_t() = default;
};

/** Tag value for multi-threaded execution.

    @par Example
    @code
    corosio::io_context ioc;
    burl::session s(ioc, burl::multithreaded);
    // Safe to call ioc.run() from multiple threads
    @endcode
*/
inline constexpr multithreaded_t multithreaded{};

//----------------------------------------------------------

/** Thread count configuration for built-in io_context.

    Specifies the number of threads to use when session owns
    its io_context. If count > 1, the session automatically
    uses a strand for thread safety.
*/
struct threads
{
    unsigned count;

    /** Constructor.

        @param n Number of threads to use
    */
    explicit constexpr
    threads(unsigned n) noexcept
        : count(n)
    {
    }
};

//----------------------------------------------------------

/** TLS verification configuration.
*/
struct verify_config
{
    /// Whether to verify the server's certificate
    bool verify_peer = true;

    /// Path to CA certificate file (PEM format)
    std::string ca_file;

    /// Path to directory containing CA certificates
    std::string ca_path;

    /// Hostname to verify against (empty = use URL host)
    std::string hostname;
};

//----------------------------------------------------------

/** Options for individual HTTP requests.

    These options override session defaults for a single request.
*/
struct request_options
{
    /// Additional headers to send with this request
    std::optional<http::fields> headers;

    /// JSON body to send (sets Content-Type: application/json)
    std::optional<std::string> json;

    /// Form data to send (sets Content-Type: application/x-www-form-urlencoded)
    std::optional<std::string> data;

    /// Request timeout (overrides session default)
    std::optional<std::chrono::milliseconds> timeout;

    /// Maximum redirects to follow (overrides session default)
    std::optional<int> max_redirects;

    /// Whether to allow redirects (default: true)
    std::optional<bool> allow_redirects;

    /// Whether to verify TLS certificates (overrides session default)
    std::optional<bool> verify;

    /// Authentication to use for this request
    std::shared_ptr<auth_base> auth;
};

} // namespace burl
} // namespace boost

#endif
