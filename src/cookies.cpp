//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/cookies.hpp>

#include <algorithm>
#include <sstream>

namespace boost {
namespace burl {

//----------------------------------------------------------
// cookie
//----------------------------------------------------------

bool
cookie::is_expired() const noexcept
{
    if (!expires)
        return false;  // Session cookie never expires
    
    return std::chrono::system_clock::now() > *expires;
}

bool
cookie::matches(urls::url_view url) const
{
    // TODO: Implementation steps:
    // 1. Check domain matching (RFC 6265 Section 5.1.3)
    //    - Exact match or domain suffix with dot prefix
    // 2. Check path matching (RFC 6265 Section 5.1.4)
    //    - Path prefix match
    // 3. Check secure flag (only send over HTTPS)
    // 4. Check expiration
    
    // Placeholder implementation
    if (is_expired())
        return false;
    
    if (secure && url.scheme_id() != urls::scheme::https)
        return false;
    
    // Domain check (simplified)
    auto host = url.host();
    if (domain != host)
    {
        // Check if host ends with .domain
        if (host.size() <= domain.size())
            return false;
        // TODO: Proper domain suffix matching
    }
    
    // Path check (simplified)
    auto req_path = url.path();
    if (req_path.empty())
        req_path = "/";
    
    if (!req_path.starts_with(path))
        return false;
    
    return true;
}

//----------------------------------------------------------
// cookie_jar
//----------------------------------------------------------

void
cookie_jar::set(cookie c)
{
    // TODO: Implementation steps:
    // 1. Find existing cookie with same (name, domain, path)
    // 2. If found, replace it
    // 3. If not found, add new cookie
    // 4. Consider max cookie limits per domain
    
    // Remove existing cookie with same key
    auto it = std::find_if(cookies_.begin(), cookies_.end(),
        [&](cookie const& existing) {
            return existing.name == c.name &&
                   existing.domain == c.domain &&
                   existing.path == c.path;
        });
    
    if (it != cookies_.end())
        cookies_.erase(it);
    
    cookies_.push_back(std::move(c));
}

void
cookie_jar::set_from_header(
    std::string_view set_cookie_header,
    urls::url_view request_url)
{
    // TODO: Implementation steps:
    // 1. Parse Set-Cookie header (RFC 6265 Section 5.2)
    // 2. Extract cookie-name and cookie-value
    // 3. Parse attributes: Expires, Max-Age, Domain, Path, Secure, HttpOnly, SameSite
    // 4. Apply default domain/path from request URL if not specified
    // 5. Validate domain (can't set for different domain)
    // 6. Create cookie and call set()
    
    cookie c;
    
    // Find first semicolon to separate name=value from attributes
    auto semi = set_cookie_header.find(';');
    auto name_value = set_cookie_header.substr(0, semi);
    
    // Parse name=value
    auto eq = name_value.find('=');
    if (eq == std::string_view::npos)
        return;  // Invalid
    
    c.name = std::string(name_value.substr(0, eq));
    c.value = std::string(name_value.substr(eq + 1));
    
    // Default domain and path from request
    c.domain = std::string(request_url.host());
    c.path = "/";
    
    // TODO: Parse remaining attributes after semicolon
    
    set(std::move(c));
}

std::vector<cookie>
cookie_jar::get_cookies(urls::url_view url) const
{
    std::vector<cookie> result;
    
    for (auto const& c : cookies_)
    {
        if (c.matches(url))
            result.push_back(c);
    }
    
    // TODO: Sort by path length (longest first) per RFC 6265
    
    return result;
}

std::string
cookie_jar::get_cookie_header(urls::url_view url) const
{
    auto cookies = get_cookies(url);
    
    if (cookies.empty())
        return {};
    
    std::ostringstream oss;
    bool first = true;
    
    for (auto const& c : cookies)
    {
        if (!first)
            oss << "; ";
        first = false;
        oss << c.name << "=" << c.value;
    }
    
    return oss.str();
}

void
cookie_jar::remove(
    std::string_view name,
    std::string_view domain,
    std::string_view path)
{
    auto it = std::find_if(cookies_.begin(), cookies_.end(),
        [&](cookie const& c) {
            return c.name == name &&
                   c.domain == domain &&
                   c.path == path;
        });
    
    if (it != cookies_.end())
        cookies_.erase(it);
}

void
cookie_jar::remove_expired()
{
    auto it = std::remove_if(cookies_.begin(), cookies_.end(),
        [](cookie const& c) { return c.is_expired(); });
    
    cookies_.erase(it, cookies_.end());
}

void
cookie_jar::clear()
{
    cookies_.clear();
}

} // namespace burl
} // namespace boost
