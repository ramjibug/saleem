# Bug Bounty Recon Notes

---

## Table of Contents

1. [Certificate Transparency (CT)](#1-certificate-transparency-ct)
2. [Google Dorking](#2-google-dorking)
3. [JavaScript Recon — LinkFinder & JSParser](#3-javascript-recon--linkfinder--jsparser)
4. [Parameter Discovery & Testing](#4-parameter-discovery--testing)
5. [Google Dork Operators — Complete Reference](#5-google-dork-operators--complete-reference)
6. [File Types & Extensions — Complete Reference](#6-file-types--extensions--complete-reference)
7. [High-Value Dork Combos — Copy-Paste Ready](#7-high-value-dork-combos--copy-paste-ready)
8. [Recon Workflow — Start to Finish](#8-recon-workflow--start-to-finish)

---

## 1. Certificate Transparency (CT)

**What:** An open framework (RFC 6962) where CAs publicly log every SSL/TLS certificate into append-only, verifiable log servers. Anyone can query them.

**Why it matters:** When a company gets an SSL cert for `internal-api.target.com`, that name is recorded publicly — even if the subdomain is not in DNS, not indexed, and not linked anywhere.

### What You Can Find

| Finding                  | Example                                              |
|--------------------------|------------------------------------------------------|
| Hidden subdomains        | dev.target.com, staging.target.com, admin.target.com |
| Wildcard patterns        | app-v2.target.com, api-staging.target.com            |
| Historical certificates  | Expired certs reveal old infra and acquisitions      |
| Related domains (SANs)   | One cert covering target.com + target-internal.com   |

### Tools & Commands

```bash
# crt.sh — free CT log search
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Amass — automated CT + passive enum
amass enum -passive -d target.com

# Subfinder — fast passive subdomain enum
subfinder -d target.com -silent

# Censys / Shodan — CT data + port scans
# Use their web interfaces or APIs
```

### Key Advantage

- Completely passive (no packets touch the target)
- Legal, fast, free
- Surfaces assets the target forgot about

---

## 2. Google Dorking

**What:** Using Google's advanced search operators to find information that was indexed but not meant to be easily discoverable.

### Core Operators

| Operator     | Purpose                  | Example                                    |
|--------------|--------------------------|--------------------------------------------|
| `site:`      | Limit to a domain        | `site:target.com`                          |
| `intitle:`   | Keywords in page title   | `intitle:"index of" site:target.com`       |
| `inurl:`     | Keywords in URL          | `inurl:admin site:target.com`              |
| `filetype:`  | Find specific file types | `filetype:pdf site:target.com`             |
| `ext:`       | File extension           | `ext:sql site:target.com`                  |
| `intext:`    | Keywords in body text    | `intext:"sql syntax" site:target.com`      |
| `-`          | Exclude terms            | `site:target.com -www`                     |
| `"..."`      | Exact phrase match       | `"default password" site:target.com`       |
| `OR`         | Either term              | `inurl:admin OR inurl:login`               |
| `*`          | Wildcard                 | `site:*.target.com`                        |

### What Each Dork Reveals

```
# Exposed files (configs, credentials, DB dumps)
site:target.com filetype:env OR filetype:log OR filetype:sql

# Login panels
site:target.com inurl:admin OR inurl:login OR inurl:dashboard

# Directory listings (misconfigured servers)
site:target.com intitle:"index of"

# Subdomains (indexed but unlisted)
site:*.target.com -www

# Sensitive documents
site:target.com filetype:xlsx OR filetype:docx confidential

# Error pages (tech stack leaks, potential SQLi)
site:target.com intext:"sql syntax"
```

### Compound Dork Example

```
site:target.com -www -video -developer ext:html inurl:login intitle:admin
```

This finds: HTML pages on target.com (excluding www, video, developer subdomains) that have "login" in the URL and "admin" in the title.

---

## 3. JavaScript Recon — LinkFinder & JSParser

### Purpose

After discovering subdomains and endpoints, analyze JavaScript files to find hidden API routes, internal URLs, and undocumented endpoints.

### LinkFinder

- **What:** Extracts URLs and endpoints from JavaScript files
- **Finds:** `/api/v1/users`, `/login`, `/admin`, `/internal/config`
- **Focus:** Link and endpoint extraction

```bash
# Usage
python3 linkfinder.py -i https://target.com/app.js -o cli

# Bulk — run on all JS files
python3 linkfinder.py -i https://target.com -d -o results.html
```

### JSParser

- **What:** Parses JavaScript files to extract URLs and endpoints
- **Finds:** Same type of endpoints, different parsing approach
- **Focus:** URL and endpoint discovery from JS source

### When to Use

```
Subdomain discovery
    → Find JS files (look in page source, use tools like gau/waybackurls)
        → Run LinkFinder / JSParser on each JS file
            → Inspect discovered endpoints
                → Test in-scope endpoints for vulnerabilities
```

---

## 4. Parameter Discovery & Testing

### Finding Parameters via Dorking

```
site:target.com inurl:id=
site:target.com inurl:search=
site:target.com inurl:page=
site:target.com inurl:redirect=
site:target.com inurl:url=
site:target.com inurl:file=
site:target.com inurl:category=
site:target.com inurl:action=
```

### What to Test on Each Parameter

| Test Type          | What to Check                                                       | Example                                        |
|--------------------|---------------------------------------------------------------------|------------------------------------------------|
| **IDOR**           | Change `id` value to access another user's data                     | `/api/user?id=1` → try `id=2`                 |
| **XSS**            | Check if input like `search` is reflected unsafely                  | `?search=<script>alert(1)</script>`            |
| **Business Logic** | Change `price`, `quantity`, `discount` to alter transactions        | `?price=0.01` or `?quantity=-1`                |
| **Access Control** | Access restricted data/actions without required permissions         | Remove auth header, change role param          |
| **SQLi**           | Test parameters for SQL injection                                   | `?id=1' OR 1=1--`                              |
| **SSRF**           | Test `url=` or `redirect=` for server-side request forgery          | `?url=http://169.254.169.254/`                 |
| **LFI/RFI**        | Test `file=` or `page=` for file inclusion                         | `?file=../../../../etc/passwd`                 |
| **Open Redirect**  | Test `redirect=` for redirecting to external sites                  | `?redirect=https://evil.com`                   |

---

## 5. Google Dork Operators — Complete Reference

| Operator       | Purpose                      | Example                                  |
|----------------|------------------------------|------------------------------------------|
| `site:`        | Restrict to domain           | `site:target.com`                        |
| `inurl:`       | Keyword in URL               | `inurl:wp-admin site:target.com`         |
| `intitle:`     | Keyword in page title        | `intitle:"index of"`                     |
| `intext:`      | Keyword in body text         | `intext:"sql syntax error"`              |
| `filetype:`    | File extension               | `filetype:pdf`                           |
| `ext:`         | Same as filetype             | `ext:env`                                |
| `cache:`       | Google's cached version      | `cache:target.com`                       |
| `link:`        | Pages linking to URL         | `link:target.com`                        |
| `related:`     | Similar sites                | `related:target.com`                     |
| `info:`        | Page info summary            | `info:target.com`                        |
| `allinurl:`    | All words must be in URL     | `allinurl:admin login`                   |
| `allintitle:`  | All words must be in title   | `allintitle:admin panel`                 |
| `allintext:`   | All words must be in body    | `allintext:username password`            |
| `"..."`        | Exact phrase                 | `"default password"`                     |
| `OR`           | Either term                  | `admin OR login`                         |
| `-`            | Exclude term                 | `site:target.com -www`                   |
| `*`            | Wildcard                     | `site:*.target.com`                      |
| `..`           | Number range                 | `"port 8000..9000"`                      |
| `before:`      | Before date                  | `site:target.com before:2025-01-01`      |
| `after:`       | After date                   | `site:target.com after:2025-01-01`       |

---

## 6. File Types & Extensions — Complete Reference

### Documents & Spreadsheets

| Extension                        | What It Finds                                        |
|----------------------------------|------------------------------------------------------|
| `filetype:pdf`                   | PDFs — reports, invoices, internal docs              |
| `filetype:doc` / `filetype:docx` | Word documents                                      |
| `filetype:xls` / `filetype:xlsx` | Excel spreadsheets — data dumps, user lists         |
| `filetype:ppt` / `filetype:pptx` | PowerPoint — internal presentations, arch diagrams  |
| `filetype:odt` / `filetype:ods`  | OpenDocument files                                  |
| `filetype:rtf`                   | Rich text files                                      |
| `filetype:csv`                   | Raw data exports, user lists                         |
| `filetype:txt`                   | Plain text — readmes, notes, passwords               |

### Config & Credential Files

| Extension          | What It Finds                                    |
|--------------------|--------------------------------------------------|
| `ext:env`          | `.env` files — API keys, DB passwords, secrets   |
| `ext:conf` / `ext:cfg` | Server/app config files                     |
| `ext:ini`          | Windows/app configuration                        |
| `ext:yaml` / `ext:yml` | YAML configs — Docker, CI/CD, Kubernetes    |
| `ext:toml`         | Rust/Python configs                              |
| `ext:xml`          | XML configs, sitemaps, API definitions           |
| `ext:json`         | JSON configs, API responses, package files       |
| `ext:properties`   | Java application configs                         |
| `ext:htaccess`     | Apache access rules, redirects, auth             |
| `ext:htpasswd`     | Apache password files                            |
| `ext:pem` / `ext:key` / `ext:crt` | SSL certs and private keys         |
| `ext:p12` / `ext:pfx` | Certificate bundles with private keys        |
| `ext:ovpn`         | OpenVPN config files                             |

### Database Files

| Extension                          | What It Finds                          |
|------------------------------------|----------------------------------------|
| `ext:sql`                          | SQL dumps — full database exports      |
| `ext:db` / `ext:sqlite` / `ext:sqlite3` | SQLite databases                 |
| `ext:mdb` / `ext:accdb`           | MS Access databases                    |
| `ext:bak`                          | Backup files — often DB or config      |
| `ext:dump`                         | Database/memory dumps                  |

### Code & Source Files

| Extension                  | What It Finds                              |
|----------------------------|--------------------------------------------|
| `ext:php`                  | PHP source — can reveal logic, SQLi        |
| `ext:asp` / `ext:aspx`    | ASP.NET source                             |
| `ext:jsp`                  | Java Server Pages                          |
| `ext:py`                   | Python scripts                             |
| `ext:rb`                   | Ruby scripts                               |
| `ext:js`                   | JavaScript — API endpoints, keys           |
| `ext:sh` / `ext:bash`     | Shell scripts — deployment, cron jobs      |
| `ext:pl`                   | Perl scripts                               |
| `ext:cgi`                  | CGI scripts                                |
| `ext:java`                 | Java source code                           |

### Log & Debug Files

| Extension      | What It Finds                                      |
|----------------|-----------------------------------------------------|
| `ext:log`      | Application/server logs — errors, IPs, usernames    |
| `ext:error`    | Error logs                                          |
| `ext:debug`    | Debug output                                        |
| `ext:trace`    | Stack traces                                        |

### Backup & Archive Files

| Extension                  | What It Finds                                      |
|----------------------------|----------------------------------------------------|
| `ext:bak`                  | Backup of any file                                 |
| `ext:old`                  | Old versions of files                              |
| `ext:orig`                 | Original files before edits                        |
| `ext:swp` / `ext:swo`     | Vim swap files — may contain source code           |
| `ext:save`                 | Saved copies                                       |
| `ext:tmp`                  | Temp files                                         |
| `ext:zip` / `ext:tar` / `ext:gz` | Archives — full project exports             |
| `ext:rar` / `ext:7z`      | Compressed archives                                |

---

## 7. High-Value Dork Combos — Copy-Paste Ready

### Credentials & Secrets

```
site:target.com ext:env OR ext:yml OR ext:conf "password" OR "secret" OR "api_key"
site:target.com filetype:log "password" OR "token"
site:target.com intitle:"index of" ".env"
site:target.com intitle:"index of" ".git"
```

### Exposed Admin Panels

```
site:target.com inurl:admin OR inurl:cpanel OR inurl:phpmyadmin OR inurl:wp-login
site:target.com intitle:"dashboard" OR intitle:"admin" OR intitle:"login"
site:target.com inurl:wp-admin OR inurl:wp-login
```

### Directory Listings (Misconfigured Servers)

```
site:target.com intitle:"index of" "parent directory"
site:target.com intitle:"index of" "backup"
site:target.com intitle:"index of" "password"
```

### Database Leaks

```
site:target.com ext:sql OR ext:db OR ext:bak
site:target.com "INSERT INTO" OR "CREATE TABLE" ext:sql
site:target.com filetype:sql "password"
```

### Error Messages (Tech Stack Fingerprinting)

```
site:target.com intext:"Fatal error" OR intext:"Warning:" ext:php
site:target.com intext:"sql syntax" OR intext:"mysql_fetch"
site:target.com intext:"stack trace" OR intext:"at java." OR intext:"Traceback"
site:target.com intext:"ORA-" OR intext:"PLS-"
```

### API & Infrastructure Discovery

```
site:target.com ext:xml "sitemap"
site:target.com filetype:wsdl OR filetype:wadl
site:target.com ext:json "api" OR "endpoint"
site:target.com inurl:swagger OR inurl:api-docs
site:target.com inurl:graphql OR inurl:graphiql
```

### Subdomain Discovery

```
site:*.target.com -www -mail -blog
site:*.target.com -www -video -developer
```

### Sensitive Documents

```
site:target.com filetype:pdf "confidential" OR "internal" OR "not for distribution"
site:target.com filetype:xlsx "password" OR "credentials" OR "employee"
site:target.com filetype:docx "internal use only"
```

### Parameter Discovery

```
site:target.com inurl:id=
site:target.com inurl:search=
site:target.com inurl:page=
site:target.com inurl:redirect=
site:target.com inurl:url=
site:target.com inurl:file=
```

---

## 8. Recon Workflow — Start to Finish

```
Step 1: Passive Subdomain Enumeration
    ├── Certificate Transparency  →  crt.sh, Censys
    ├── Google Dorking             →  site:*.target.com
    ├── DNS Enumeration            →  dig, nslookup, dnsrecon
    ├── Subfinder / Amass          →  Automated passive enum
    └── WHOIS & Reverse WHOIS      →  whois, SecurityTrails

Step 2: Infrastructure Mapping
    ├── Resolve IPs                →  dig target.com +short
    ├── ASN Lookup                 →  bgp.he.net, ipinfo.io
    ├── Reverse DNS                →  dig -x <IP>
    ├── Port Scanning              →  Shodan, Censys (passive)
    └── Tech Stack                 →  HTTP headers, Wappalyzer

Step 3: Content Discovery
    ├── Google Dorking             →  All dork combos above
    ├── Wayback Machine            →  web.archive.org, gau, waybackurls
    ├── Robots.txt / Sitemap.xml   →  curl target.com/robots.txt
    └── Directory Bruting          →  ffuf, dirsearch, gobuster

Step 4: JavaScript Analysis
    ├── Find JS files              →  View source, gau, waybackurls
    ├── LinkFinder                 →  Extract endpoints from JS
    ├── JSParser                   →  Parse JS for URLs
    └── Manual review              →  Look for API keys, secrets

Step 5: Parameter Testing
    ├── IDOR                       →  Change id values between accounts
    ├── XSS                        →  Test reflected/stored inputs
    ├── SQLi                       →  Test query parameters
    ├── SSRF                       →  Test url/redirect parameters
    ├── LFI/RFI                    →  Test file/page parameters
    ├── Open Redirect              →  Test redirect parameters
    ├── Business Logic             →  Test price/quantity/discount
    └── Access Control             →  Test without auth, change roles
```

---

## Quick Reference — Resources

| Resource                                                                 | Purpose                         |
|--------------------------------------------------------------------------|---------------------------------|
| [crt.sh](https://crt.sh)                                                | CT log search                   |
| [Shodan](https://shodan.io)                                             | Port scans + CT data            |
| [Censys](https://censys.io)                                             | Internet-wide scan data         |
| [SecurityTrails](https://securitytrails.com)                            | Historical DNS                  |
| [Wayback Machine](https://web.archive.org)                              | Historical snapshots            |
| [GHDB — Exploit-DB](https://www.exploit-db.com/google-hacking-database) | Google Hacking Database         |
| [bgp.he.net](https://bgp.he.net)                                       | ASN / BGP lookups               |
| [ipinfo.io](https://ipinfo.io)                                          | IP info + ASN                   |

---

*Notes compiled for authorized security testing and bug bounty recon.*
