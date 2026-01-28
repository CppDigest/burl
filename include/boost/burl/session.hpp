//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SESSION_HPP
#define BOOST_BURL_SESSION_HPP

#include <boost/burl/fwd.hpp>
#include <boost/burl/auth.hpp>
#include <boost/burl/body_tags.hpp>
#include <boost/burl/cookies.hpp>
#include <boost/burl/error.hpp>
#include <boost/burl/options.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/io_task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ssl_context.hpp>
#include <boost/http/fields.hpp>
#include <boost/http/method.hpp>
#include <boost/json/value.hpp>
#include <boost/url/url_view.hpp>

#include <memory>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** HTTP client session.

    A session manages HTTP connections, cookies, authentication,
    and default headers. It supports both HTTP and HTTPS connections
    with automatic connection pooling and redirect handling.

    The session can operate in two modes:

    **Built-in io_context mode**: The session owns its io_context
    and manages worker threads internally.

    **External io_context mode**: The session uses an io_context
    provided by the user.

    For multi-threaded operation, the session automatically uses
    a strand to ensure thread safety.

    @par Thread Safety
    A single session instance is not thread-safe. However, multiple
    sessions can be used from different threads.

    @par Example
    @code
    // Built-in single-threaded
    burl::session s;
    
    // Built-in multi-threaded with 4 threads
    burl::session s(burl::threads{4});
    
    // External io_context, single-threaded
    corosio::io_context ioc;
    burl::session s(ioc);
    
    // External io_context, multi-threaded
    burl::session s(ioc, burl::multithreaded);
    @endcode
*/
class session
{
    struct impl;
    std::unique_ptr<impl> impl_;

public:
    //------------------------------------------------------
    // Construction
    //------------------------------------------------------

    /** Construct with built-in io_context (single-threaded).

        Creates a session that owns its io_context. The io_context
        is run when run() is called, blocking until all work completes.
    */
    session();

    /** Construct with built-in io_context (multi-threaded).

        Creates a session that owns its io_context and runs it on
        the specified number of threads. A strand is used for
        thread safety.

        @param t Thread configuration
    */
    explicit
    session(threads t);

    /** Construct with external io_context (single-threaded).

        Creates a session that uses the provided io_context.
        The user is responsible for running the io_context.

        @param ioc Reference to the io_context to use
    */
    explicit
    session(corosio::io_context& ioc);

    /** Construct with external io_context (multi-threaded).

        Creates a session that uses the provided io_context which
        will be run from multiple threads. A strand is used for
        thread safety.

        @param ioc Reference to the io_context to use
        @param tag Multi-threaded tag
    */
    session(corosio::io_context& ioc, multithreaded_t tag);

    /** Destructor.

        Closes all connections and stops any internal threads.
    */
    ~session();

    /** Move constructor.
    */
    session(session&&) noexcept;

    /** Move assignment operator.
    */
    session&
    operator=(session&&) noexcept;

    // Non-copyable
    session(session const&) = delete;
    session& operator=(session const&) = delete;

    //------------------------------------------------------
    // io_context management
    //------------------------------------------------------

    /** Run the internal io_context.

        Only valid when using built-in io_context mode.
        Blocks until all work completes or close() is called.

        @throws std::logic_error if using external io_context
    */
    void
    run();

    /** Get a reference to the io_context.

        Returns the io_context used by this session, whether
        built-in or external.
    */
    corosio::io_context&
    get_io_context() noexcept;

    //------------------------------------------------------
    // TLS configuration
    //------------------------------------------------------

    /** Get the TLS context.

        Returns a reference to the SSL context used for HTTPS
        connections. Use this to configure certificates and
        verification settings.

        @par Example
        @code
        burl::session s;
        auto& ctx = s.tls_context();
        ctx.set_verify_mode(corosio::ssl::verify_peer);
        ctx.load_verify_file("/path/to/ca-bundle.crt");
        @endcode
    */
    corosio::ssl_context&
    tls_context() noexcept;

    /** Get the TLS context (const).
    */
    corosio::ssl_context const&
    tls_context() const noexcept;

    /** Set a custom TLS context.

        Replaces the default TLS context with a user-provided one.
        The context is shared, so changes affect all sessions
        using the same context.

        @param ctx The TLS context to use
    */
    void
    set_tls_context(std::shared_ptr<corosio::ssl_context> ctx);

    //------------------------------------------------------
    // Session configuration
    //------------------------------------------------------

    /** Get default headers.

        Returns the headers that are sent with every request.
        Modify these to set defaults like User-Agent.

        @par Example
        @code
        burl::session s;
        s.headers().set(http::field::user_agent, "MyApp/1.0");
        @endcode
    */
    http::fields&
    headers() noexcept;

    /** Get default headers (const).
    */
    http::fields const&
    headers() const noexcept;

    /** Get the cookie jar.

        Returns the cookie storage for this session. Cookies
        are automatically managed for all requests.
    */
    cookie_jar&
    cookies() noexcept;

    /** Get the cookie jar (const).
    */
    cookie_jar const&
    cookies() const noexcept;

    /** Set default authentication.

        Sets the authentication used for all requests that
        don't specify their own auth in request_options.

        @param auth The authentication to use
    */
    void
    set_auth(std::shared_ptr<auth_base> auth);

    /** Set default TLS verification.

        @param v Verification configuration
    */
    void
    set_verify(verify_config v);

    /** Set maximum number of redirects to follow.

        @param n Maximum redirects (0 = don't follow)
    */
    void
    set_max_redirects(int n);

    /** Set default request timeout.

        @param timeout Timeout duration
    */
    void
    set_timeout(std::chrono::milliseconds timeout);

    //------------------------------------------------------
    // HTTP request methods - string body (default)
    //------------------------------------------------------

    /** Perform an HTTP request.

        @param method HTTP method
        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    request(http::method method, urls::url_view url, request_options opts = {});

    /** Perform an HTTP GET request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    get(urls::url_view url, request_options opts = {});

    /** Perform an HTTP POST request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    post(urls::url_view url, request_options opts = {});

    /** Perform an HTTP PUT request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    put(urls::url_view url, request_options opts = {});

    /** Perform an HTTP PATCH request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    patch(urls::url_view url, request_options opts = {});

    /** Perform an HTTP DELETE request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    delete_(urls::url_view url, request_options opts = {});

    /** Perform an HTTP HEAD request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    head(urls::url_view url, request_options opts = {});

    /** Perform an HTTP OPTIONS request.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    options(urls::url_view url, request_options opts = {});

    //------------------------------------------------------
    // HTTP request methods - explicit string body
    //------------------------------------------------------

    /** Perform an HTTP GET request with string body.

        @param url Request URL
        @param tag String body tag
        @param opts Request options

        @return An awaitable yielding `(error_code, response<std::string>)`
    */
    capy::io_task<response<std::string>>
    get(urls::url_view url, as_string_t tag, request_options opts = {});

    //------------------------------------------------------
    // HTTP request methods - JSON body
    //------------------------------------------------------

    /** Perform an HTTP GET request with JSON parsing.

        The response body is parsed as JSON into a json::value.

        @param url Request URL
        @param tag JSON body tag
        @param opts Request options

        @return An awaitable yielding `(error_code, response<json::value>)`
    */
    capy::io_task<response<json::value>>
    get(urls::url_view url, as_json_t tag, request_options opts = {});

    /** Perform an HTTP POST request with JSON parsing.

        @param url Request URL
        @param tag JSON body tag
        @param opts Request options

        @return An awaitable yielding `(error_code, response<json::value>)`
    */
    capy::io_task<response<json::value>>
    post(urls::url_view url, as_json_t tag, request_options opts = {});

    //------------------------------------------------------
    // HTTP request methods - custom type deserialization
    //------------------------------------------------------

    /** Perform an HTTP GET request with custom type deserialization.

        The response body is deserialized into type T using
        Boost.Describe or C++26 reflection.

        @tparam T The type to deserialize into
        @param url Request URL
        @param tag Type deserialization tag
        @param opts Request options

        @return An awaitable yielding `(error_code, response<T>)`
    */
    template<class T>
    capy::io_task<response<T>>
    get(urls::url_view url, as_type_t<T> tag, request_options opts = {});

    /** Perform an HTTP POST request with custom type deserialization.

        @tparam T The type to deserialize into
        @param url Request URL
        @param tag Type deserialization tag
        @param opts Request options

        @return An awaitable yielding `(error_code, response<T>)`
    */
    template<class T>
    capy::io_task<response<T>>
    post(urls::url_view url, as_type_t<T> tag, request_options opts = {});

    //------------------------------------------------------
    // HTTP request methods - streaming
    //------------------------------------------------------

    /** Perform an HTTP GET request with streaming response.

        Returns a streamed_response where the body can be read
        incrementally via a buffer source.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, streamed_response)`
    */
    capy::io_task<streamed_response>
    get_streamed(urls::url_view url, request_options opts = {});

    /** Perform an HTTP POST request with streaming response.

        @param url Request URL
        @param opts Request options

        @return An awaitable yielding `(error_code, streamed_response)`
    */
    capy::io_task<streamed_response>
    post_streamed(urls::url_view url, request_options opts = {});

    //------------------------------------------------------
    // Connection management
    //------------------------------------------------------

    /** Close all connections and stop any internal threads.

        After calling close(), the session cannot be used for
        new requests. Pending requests may be cancelled.
    */
    void
    close();
};

//----------------------------------------------------------
// Template implementations
//----------------------------------------------------------

template<class T>
capy::io_task<response<T>>
session::get(urls::url_view url, as_type_t<T>, request_options opts)
{
    // TODO: Implementation steps:
    // 1. Call get(url, as_string, opts) to get string body
    // 2. Parse JSON from string body
    // 3. Deserialize JSON into T using Boost.Describe or reflection
    // 4. Return response<T>
    
    co_return {make_error_code(error::not_implemented), {}};
}

template<class T>
capy::io_task<response<T>>
session::post(urls::url_view url, as_type_t<T>, request_options opts)
{
    // TODO: Implementation steps:
    // 1. Call post(url, as_string, opts) to get string body
    // 2. Parse JSON from string body
    // 3. Deserialize JSON into T using Boost.Describe or reflection
    // 4. Return response<T>
    
    co_return {make_error_code(error::not_implemented), {}};
}

} // namespace burl
} // namespace boost

#endif
