# Web Application Penetration Testing Checklist
> This checklist may help you to have a good methodology for bug bounty hunting

## Table of Contents
* [Recon on wildcard domain](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#recon-on-wildcard-domain)
* [Single domain](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#single-domain)
* [Information Gathering](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#information-gathering)
* [Configuration Management](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#configuration-management)
* [Secure Transmission](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#secure-transmission)
* [Authentication](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#authentication)
* [Session Management](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#session-management)
* [Authorization](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#authorization)
* [Data Validation](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#data-validation)
* [Denial of Service](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#denial-of-service)
* [Business Logic](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#business-logic)
* [Cryptography](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#cryptography)
* [Risky Functionality - File Uploads](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#risky-functionality---file-uploads)
* [Risky Functionality - Card Payment](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#risky-functionality---card-payment)
* [HTML 5](https://github.com/Esther7171/Portswigger-labs/edit/main/Check-List/Web-App-Pentesting.md#html-5)
  
## Recon on wildcard domain
* [ ] Run amass
* [ ] Run subfinder
* [ ] Run assetfinder
* [ ] Run dnsgen
* [ ] Run massdns
* [ ] Use httprobe
* [ ] Run aquatone (screenshot for alive host)
## Single Domain
### Scanning
* [ ] Nmap scan
* [ ] Burp crawler
* [ ] ffuf (directory and file fuzzing)
* [ ] hakrawler/gau/paramspider
* [ ] Linkfinder
* [ ] Url with Android application
### Manual checking
* [ ] Shodan
* [ ] Censys
* [ ] Google [dorks](https://dorks.faisalahmed.me)
* [ ] Pastebin
* [ ] Github
* [ ] OSINT
## Information Gathering
* [ ] Test for running services, web technologies, total subdomains, and directory contents.
* [ ] Check for AI integration or chatbot functionality for data extraction testing.
* [ ] Manually explore the site
* [ ] Spider/crawl for missed or hidden content
* [ ] Check for files that expose content, such as `robots.txt`, `sitemap.xml`, `.DS_Store`
* [ ] Check the caches of major search engines for publicly accessible sites
* [ ] Check for differences in content based on User Agent (eg, Mobile sites, access as a Search engine Crawler)
* [ ] Perform Web Application Fingerprinting
* [ ] Identify technologies used
* [ ] Identify user roles
* [ ] Identify application entry points
* [ ] Identify client-side code
* [ ] Identify multiple versions/channels (e.g. web, mobile web, mobile app, web services)
* [ ] Identify co-hosted and related applications
* [ ] Identify all hostnames and ports
* [ ] Identify third-party hosted content
* [ ] Identify Debug parameters
* [ ] Test Banner grabbing
* [ ] Identify cookie type
* [ ] By refreshing page check for network tab and config
## Configuration Management
* [ ] Check for commonly used application and administrative URLs
* [ ] Check for old, backup and unreferenced files
* [ ] Check HTTP methods supported and Cross Site Tracing (XST)
* [ ] Test file extensions handling
* [ ] Test for security HTTP headers (e.g. CSP, X-Frame-Options, HSTS)
* [ ] Test for policies (e.g. Flash, Silverlight, robots)
* [ ] Test for non-production data in live environment, and vice-versa
* [ ] Check for sensitive data in client-side code (e.g. API keys, credentials)
* [ ] Check [WaF]((https://github.com/EnableSecurity/wafw00f) on website 
* [ ] Check parameters in [JavaScript files](https://github.com/GerbenJavado/LinkFinder)
* [ ] Test for [subdomain takeover](https://github.com/PentestPad/subzy) and NS record
* [ ] Check for Mail spoof, CNMAE, A and DNS record and check for zone transfer attack
## Secure Transmission
* [ ] Check SSL Version, Algorithms, Key length
* [ ] Check for Digital Certificate Validity (Duration, Signature and CN)
* [ ] Check credentials only delivered over HTTPS
* [ ] Check that the login form is delivered over HTTPS
* [ ] Check session tokens only delivered over HTTPS
* [ ] Check if HTTP Strict Transport Security (HSTS) in use
## Authentication
* [ ] Test for user enumeration
* [ ] Test for authentication bypass
* [ ] Test for bruteforce protection
* [ ] Test password quality rules
* [ ] Test remember me functionality
* [ ] Test for autocomplete on password forms/input
* [ ] Test password reset and/or recovery
* [ ] Test password change process
* [ ] Manipulating OTP
* [ ] Test CAPTCHA
* [ ] Test multi factor authentication
* [ ] Test for logout functionality presence
* [ ] Test for cache management on HTTP (eg Pragma, Expires, Max-age)
* [ ] Test for default logins
* [ ] Test for user-accessible authentication history
* [ ] Test for out-of channel notification of account lockouts and successful password changes
* [ ] Test for consistent authentication across applications with shared authentication schema / SSO
* [ ] Test credential entry with correct and incorrect username/password combinations, and verify the responses and response codes
* [ ] Verify that after changing a username or password, the old username or password cannot be used to log in
* [ ] Ensure that when a user changes their username or password, all existing sessions are invalidated (logged out), forcing re-authentication with the new credentials
* [ ] Ensure account‑centric brute‑force protections and session handling across devices: implement rate‑limiting/account lockout and MFA, and invalidate all existing sessions when credentials change so old usernames/passwords or tokens cannot be reused
## Session Management
* [ ] Establish how session management is handled in the application (eg, tokens in cookies, token in URL)
* [ ] Check session tokens for cookie flags (httpOnly and secure)
* [ ] Check session cookie scope (path and domain)
* [ ] Check session cookie duration (expires and max-age)
* [ ] Check session termination after a maximum lifetime
* [ ] Check session termination after relative timeout
* [ ] Check session termination after logout
* [ ] Test to see if users can have multiple simultaneous sessions
* [ ] Test session cookies for randomness
* [ ] Confirm that new session tokens are issued on login, role change and logout
* [ ] Test for consistent session management across applications with shared session management
* [ ] Test for session puzzling
* [ ] Test for CSRF and clickjacking
## Authorization
* [ ] Test for path traversal
* [ ] Test for bypassing authorization schema
* [ ] Test for bypassing OTP
* [ ] Test for vertical Access control problems (a.k.a. Privilege Escalation)
* [ ] Test for horizontal Access control problems (between two users at the same privilege level)
* [ ] Test for missing authorization
* [ ] Test that the same name or email cannot be registered
* [ ] Ensure temporary emails are rejected.
* [ ] Test for double‑encoding, malformed/false encodings, special‑character encodings (e.g., null‑byte `%00`, Unicode homoglyphs/overlong sequences), and weak/insecure hashes (e.g., unsalted MD5/SHA1 or predictable hashes in URLs/responses) to ensure the server canonicalizes inputs, blocks traversal or unauthorized access, and does not expose reversible or predictable hashed secrets
## Data Validation
* [ ] Test for Reflected Cross Site Scripting
* [ ] Test for Stored Cross Site Scripting
* [ ] Test for DOM based Cross Site Scripting
* [ ] Test for Cross Site Flashing
* [ ] Test for HTML Injection
* [ ] Test for SQL Injection
* [ ] Test for LDAP Injection
* [ ] Test for ORM Injection
* [ ] Test for XML Injection
* [ ] Test for XXE Injection
* [ ] Test for SSI Injection
* [ ] Test for XPath Injection
* [ ] Test for XQuery Injection
* [ ] Test for IMAP/SMTP Injection
* [ ] Test for Code Injection
* [ ] Test for Expression Language Injection
* [ ] Test for Command Injection
* [ ] Test for Overflow (Stack, Heap and Integer)
* [ ] Test for Format String
* [ ] Test for incubated vulnerabilities
* [ ] Test for HTTP files
* [ ] Test for HTTP Splitting/Smuggling
* [ ] Test for HTTP Verb Tampering
* [ ] Test for Open Redirection
* [ ] Test for Local File Inclusion
* [ ] Test for Remote File Inclusion
* [ ] Compare client-side and server-side validation rules
* [ ] Test for NoSQL injection
* [ ] Test for HTTP parameter pollution
* [ ] Test for auto-binding
* [ ] Test for Mass Assignment
* [ ] Test for NULL/Invalid Session Cookie
* [ ] Test response manipulation and check if changing the allowed request type is possible
* [ ] Check for api respose api type and api version and api data leak
## Denial of Service
* [ ] Test for anti-automation
* [ ] Test for account lockout
* [ ] Test for HTTP protocol DoS
* [ ] Test for SQL wildcard DoS
* [ ] Test upload lottapixel image
## Business Logic
* [ ] Test for feature misuse
* [ ] Test for lack of non-repudiation
* [ ] Test for trust relationships
* [ ] Test for integrity of data
* [ ] Test for Parameter Tampering
* [ ] Test segregation of dutiess
## Cryptography
* [ ] Check if data which should be encrypted is not
* [ ] Check for wrong algorithms usage depending on context
* [ ] Check for weak algorithms usage
* [ ] Check for proper use of salting
* [ ] Check for randomness functions
## Risky Functionality - File Uploads
* [ ] Test that acceptable file types are whitelisted
* [ ] Test that file size limits, upload frequency and total file counts are defined and are enforced
* [ ] Test that file contents match the defined file type
* [ ] Test that all file uploads have Anti-Virus scanning in-place.
* [ ] Test that unsafe filenames are sanitised
* [ ] Test that uploaded files are not directly accessible within the web root
* [ ] Test that uploaded files are not served on the same hostname/port
* [ ] Test that files and other media are integrated with the authentication and authorisation schemas
## Risky Functionality - Card Payment
* [ ] Test for known vulnerabilities and configuration issues on Web Server and Web Application
* [ ] Test for default or guessable password
* [ ] Test for non-production data in live environment, and vice-versa
* [ ] Test for Injection vulnerabilities
* [ ] Test for Buffer Overflows
* [ ] Test for Insecure Cryptographic Storage
* [ ] Test for Insufficient Transport Layer Protection
* [ ] Test for Improper Error Handling
* [ ] Test for all vulnerabilities with a CVSS v2 score > 4.0
* [ ] Test for Authentication and Authorization issues
* [ ] Test for CSRF
* [ ] Test for Cloud Location attached to web app
## HTML 5
* [ ] Test Web Messaging
* [ ] Test for Web Storage SQL injection
* [ ] Check CORS implementation
* [ ] Check Offline Web Application

# API Security Checklist

Checklist of the most important security countermeasures when designing, testing, and releasing your API.

---

## Enumeration
- [ ] Use a fuzzer for discover new APIs. For several levels.
- [ ] Enumerate restricted endpoints. For trying to bypass. Add to the final endpoint(..;/, etc).
- [ ] Modifying the request for additional parameters. For example: &admin=true.


## Authentication

- [ ] Don't use `Basic Auth`. Use standard authentication instead (e.g., [JWT](https://jwt.io/)).
- [ ] Don't reinvent the wheel in `Authentication`, `token generation`, `password storage`. Use the standards.
- [ ] Use `Max Retry` and jail features in Login.
- [ ] Use encryption on all sensitive data.
- [ ] Reusing old session tokens

### JWT (JSON Web Token)

- [ ] Use a random complicated key (`JWT Secret`) to make brute forcing the token very hard.
- [ ] Don't extract the algorithm from the header. Force the algorithm in the backend (`HS256` or `RS256`).
- [ ] Make token expiration (`TTL`, `RTTL`) as short as possible.
- [ ] Don't store sensitive data in the JWT payload, it can be decoded [easily](https://jwt.io/#debugger-io).
- [ ] Avoid storing too much data. JWT is usually shared in headers and they have a size limit.
- [ ] More attacks about JWT:
      https://www.invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities/

## Access

- [ ] Limit requests (Throttling) to avoid DDoS / brute-force attacks.
- [ ] Use HTTPS on server side with TLS 1.2+ and secure ciphers to avoid MITM (Man in the Middle Attack).
- [ ] Use `HSTS` header with SSL to avoid SSL Strip attacks.
- [ ] Turn off directory listings.
- [ ] For private APIs, allow access only from safelisted IPs/hosts.

## Authorization

### OAuth

- [ ] Always validate `redirect_uri` server-side to allow only safelisted URLs.
- [ ] Always try to exchange for code and not tokens (don't allow `response_type=token`).
- [ ] Use `state` parameter with a random hash to prevent CSRF on the OAuth authorization process.
- [ ] Define the default scope, and validate scope parameters for each application.

## Input

- [ ] Lack of input sanitization / Escaping unsafe characters.
- [ ] Use the proper HTTP method according to the operation: `GET (read)`, `POST (create)`, `PUT/PATCH (replace/update)`, and `DELETE (to delete a record)`, and respond with `405 Method Not Allowed` if the requested method isn't appropriate for the requested resource.
- [ ] Validate `content-type` on request Accept header (Content Negotiation) to allow only your supported format (e.g., `application/xml`, `application/json`, etc.) and respond with `406 Not Acceptable` response if not matched.
- [ ] Validate `content-type` of posted data as you accept (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, etc.).
- [ ] Validate user input to avoid common vulnerabilities (e.g., `XSS`, `SQL-Injection`, `Remote Code Execution`, etc.).
- [ ] Don't use any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL, but use standard Authorization header.
- [ ] Modifying referrer headers that the API may expect.
- [ ] Use only server-side encryption.
- [ ] Use an API Gateway service to enable caching, Rate Limit policies (e.g., `Quota`, `Spike Arrest`, or `Concurrent Rate Limit`) and deploy APIs resources dynamically.
- [ ] Test file uploads request.
- [ ]  Cross-site Request Forgery (CSRF) — If your API accepts the same authentication configuration that your interactive users use, then you might be vulnerable to a CSRF attack. For example, if your interactive users login and get a “SESSIONID” cookie, and that cookie can also be used to invoke API requests, then a carefully composed HTML form could make unexpected API requests on behalf of your users.
- [ ]  IDOR in body/header is more vulnerable than ID in URL. For example: {“id”:{“id”:111}}


## Processing

- [ ] Check if all the endpoints are protected behind authentication to avoid broken authentication process.
- [ ] User own resource ID should be avoided. Use `/me/orders` instead of `/user/654321/orders`.
- [ ] Don't auto-increment IDs. Use `UUID` instead.
- [ ] If you are parsing XML data, make sure entity parsing is not enabled to avoid `XXE` (XML external entity attack).
- [ ] If you are parsing XML, YAML or any other language with anchors and refs, make sure entity expansion is not enabled to avoid `Billion Laughs/XML bomb` via exponential entity expansion attack.
- [ ] Use a CDN for file uploads.
- [ ] If you are dealing with huge amount of data, use Workers and Queues to process as much as possible in background and return response fast to avoid HTTP Blocking.
- [ ] Do not forget to turn the DEBUG mode OFF.
- [ ] Use non-executable stacks when available.
- [ ] If found GET /api/v1/users/<id> try DELETE / POST to create/delete users

## Output

- [ ] Send `X-Content-Type-Options: nosniff` header.
- [ ] Send `X-Frame-Options: deny` header.
- [ ] Send `Content-Security-Policy: default-src 'none'` header.
- [ ] Remove fingerprinting headers - `X-Powered-By`, `Server`, `X-AspNet-Version`, etc.
- [ ] Force `content-type` for your response. If you return `application/json`, then your `content-type` response is `application/json`.
- [ ] Don't return sensitive data like `credentials`, `passwords`, or `security tokens`.
- [ ] Return the proper status code according to the operation completed. (e.g., `200 OK`, `400 Bad Request`, `401 Unauthorized`, `405 Method Not Allowed`, etc.).
- [ ] DoS Limit: /api/news?limit=100 -> /api/news?limit=9999999999

## Monitoring

- [ ] Use centralized logins for all services and components.
- [ ] Use agents to monitor all traffic, errors, requests, and responses.
- [ ] Use alerts for SMS, Slack, Email, Telegram, Kibana, Cloudwatch, etc.
- [ ] Ensure that you aren't logging any sensitive data like credit cards, passwords, PINs, etc.
- [ ] Use an IDS and/or IPS system to monitor your API requests and instances.

