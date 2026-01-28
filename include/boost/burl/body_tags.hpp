//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_BODY_TAGS_HPP
#define BOOST_BURL_BODY_TAGS_HPP

#include <boost/burl/fwd.hpp>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** Tag type for requesting body as string.

    When passed to session request methods, indicates the
    response body should be accumulated into a std::string.

    @see as_string
*/
struct as_string_t
{
    explicit constexpr as_string_t() = default;
};

/** Tag value for requesting body as string.

    @par Example
    @code
    auto [ec, r] = co_await session.get(url, burl::as_string);
    // r.body is std::string
    @endcode
*/
inline constexpr as_string_t as_string{};

//----------------------------------------------------------

/** Tag type for requesting body as JSON.

    When passed to session request methods, indicates the
    response body should be parsed into a boost::json::value.

    @see as_json
*/
struct as_json_t
{
    explicit constexpr as_json_t() = default;
};

/** Tag value for requesting body as JSON.

    @par Example
    @code
    auto [ec, r] = co_await session.get(url, burl::as_json);
    // r.body is json::value
    std::cout << r.body.at("name").as_string();
    @endcode
*/
inline constexpr as_json_t as_json{};

//----------------------------------------------------------

/** Tag type for requesting body as a custom type.

    When passed to session request methods, indicates the
    response body should be deserialized into the specified
    type T using Boost.Describe or C++26 reflection.

    @tparam T The type to deserialize the body into

    @see as_type
*/
template<class T>
struct as_type_t
{
    explicit constexpr as_type_t() = default;
};

/** Tag value for requesting body as a custom type.

    @tparam T The type to deserialize the body into

    @par Example
    @code
    struct User {
        std::string login;
        int id;
    };
    BOOST_DESCRIBE_STRUCT(User, (), (login, id))

    auto [ec, r] = co_await session.get(url, burl::as_type<User>);
    // r.body is User
    std::cout << r.body.login;
    @endcode
*/
template<class T>
inline constexpr as_type_t<T> as_type{};

} // namespace burl
} // namespace boost

#endif
