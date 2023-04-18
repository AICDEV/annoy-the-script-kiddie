# annoy-the-script-kiddie

## nginx

A complete configuration example with reverse proxy, simple load balancing and secure config is available inside the *./example_config* folder.

### headers

| nginx add header  |  description  |  read more |
|---------|---------------|------------|
| ```add_header Referrer-Policy same-origin; ``` | The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) should be included with requests. | [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) |
| ```add_header X-Frame-Options "DENY";``` | The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a frame, iframe, embed or object. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites. | [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) |
| ```add_header X-XSS-Protection "1;mode=block";``` | The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. | [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection) |
| ```add_header X-Content-Type-Options nosniff;``` | The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should be followed and not be changed. The header allows you to avoid MIME type sniffing by saying that the MIME types are deliberately configured. | [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) |
| ```add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";``` | The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS. | [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| ```add_header Content-Security-Policy default-src "self" always;``` | The HTTP Content-Security-Policy response header allows website administrators to control resources the user agent is allowed to load for a given page. With a few exceptions, policies mostly involve specifying server origins and script endpoints. This helps guard against cross-site scripting attacks (Cross-site_scripting). | [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) |
| ```add_header Feature-Policy "microphone 'none'; geolocation 'none'; camera 'none'" always; ``` | The HTTP Permissions-Policy header provides a mechanism to allow and deny the use of browser features in a document or within any iframe elements in the document. | [Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) |

### tls 

The TLS protocol is managed and developed by the IETF TLS Working Group. More information is available at: [https://tlswg.org/](https://tlswg.org/)

TLS config example for nginx:

```
# Services with clients that support TLS 1.3 and dont need backward compatibility
ssl_prefer_server_ciphers off;
ssl_stapling on;
ssl_stapling_verify on;

# Diffie-Hellman group
ssl_dhparam /etc/nginx/dhparam.pem;

ssl_session_tickets off;
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;

#Cipher-Suites
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA";
```

Diffie-Hellman group: This is used for s.g. perfect forward secrecy [https://en.wikipedia.org/wiki/Forward_secrecy](https://en.wikipedia.org/wiki/Forward_secrecy), which generates ephemeral session keys to ensure that an intercepted communication cannot be decrypted even if the session key is compromised.

```bash
openssl dhparam -out /etc/nginx/dhparam.pem 4096
```

### limit request zone
Rate limiting can be used for security purposes, for example to slow down brute‑force password‑guessing attacks. Read more on nginx offical blog: [https://www.nginx.com/blog/rate-limiting-nginx/](https://www.nginx.com/blog/rate-limiting-nginx/)

```
limit_req_zone $binary_remote_addr zone=limitreqsbyaddr:20m rate=15r/s;
limit_req_status 429;

upstream app.localhost {
	server localhost:8080;
}


server {
	listen 443 ssl;
	server_name app.devlab.intern;

	location / {
		limit_req zone=limitreqsbyaddr burst=10;
		proxy_pass http://app.localhost;
	}
}
```