# irongate

Customizable SSO for your website via OIDC

## Generate keys
To use irongate you need to generate a prime256v1 key pair. The private
key will be used to sign JWTs and the public key will be
used by your proxy to verify the JWTs. You can generate a
key pair with the following openssl commands:

 - Generate private key:  
   `openssl ecparam -name prime256v1 -outform der -genkey -noout -out private.der`

 - Generate public key:  
   `openssl ec -in private.der -pubout -out public.crt`

## Configuration
By default irongate will look for a `config.toml` in the
same directory. You can change the path to the config by
setting `CONFIG=/path/to/config.toml`. All config values
can also be set as environment variables with the same
name. To change the log level use the `RUST_LOG` environment
variable.

### Example configuration
Contains all possible values. All values that are not
required have the default value

```toml
# The interface to listen on
host = "127.0.0.1"

# The port to listen on
port = "8080"

# This message is displayed on every error, details will be in the server log where needed
error_message = "Something went wrong. Please try again or contact postmaster@domain.com."

# How long to wait for the IDP before invalidating the session (seconds)
auth_time = 120 # 2 Minutes

# Should irongate verify redirect URls
verify_redirect = true

# Which URLs are allowed as redirect targets. (required if verify_redirect is true)
# Wildcards (*) are allowed at the end of the URL
allowed_redirects = [
  "https://secure.domain.com/*",
  "https://vault.domain.com/landing",
]

[jwt]

# Path to the keyfile
key_path = "./private.der"

# After which time the JWT expires (minutes)
jwt_duration = 10080 # 7 Days

# Compress the JWT body
compress = false

# Include the KID in the JWT header
kid = false

[oidc]
# OIDC client id (required)
client_id = "123456789"

# OIDC Issuer / server URL (required)
issuer_url = "https://auth.domain.com"

# OIDC callback URL. Irongate will expect callbacks at /oidc/callback (required)
callback_url = "https://domain.com/oidc/callback"

# Verify the audience claim on the ID Token
verify_audience = false

# Which audiences, other than this client, to trust (required if verify_audience is true)
trusted_audiences = [
  "0987654321"
]

[cookie]
# The cookie name
name = "vouch"

# Domain to set on the cookie
domain = "domain.com"

# Path to set on the cookie
path = "/"
```

## Usage

### With HAProxy

```
frontend [...]
  
  # The domain we want to secure
  acl secure hdr(host) -i secure.domain.com
  
  # Check for the vouch cookie
  acl has_auth req.cook(vouch) -m found

  # Rewrite requested Url to /oidc/login when no vouch cookie is found
  http-request set-path /oidc/login?redirect=https://%[hdr(host)]%[capture.req.uri] if !has_auth secure
  
  # Redirect to irongate if the path starts with /oidc/
  use_backend backend_irongate if secure { path_beg /oidc/ }

  use_backend backend_secure if secure
  
backend backend_irongate
  server irongate [...]

backend backend_secure
  # Verify JWT
  http-request redirect code 302 location https://secure.domain.com/oidc/login?redirect=https://%[hdr(host)]%[capture.req.uri] unless { req.cook(vouch),jwt_verify("ES256","./public.crt") -m int 1 }
  
  server supersecure [...]
```

### With Nginx

```
server{
  server_name secure.domain.com;
    
  # Use the Nginx auth_request module to verify the JWTs
  auth_request /oidc/verify;
  error_page 401 = @auth;
    
  # Use /oidc/ for irongate
  location /oidc/ {
    # You could do some caching here, but irongate
    # takes ~0.6 ms to respond.
    # The caching overhead is probably not worth it.
    proxy_pass http://127.0.0.1:8080;
    proxy_pass_request_body off;
  }

  # Redirect to irongate login
  location @auth {
    # You could probably rewrite the url and proxy_pass directly to irongate here
    # which would save 1 request, similar to what i did with haproxy.
    return 302 https://spacegli.de/oidc/login?redirect=https://$http_host$request_uri;
  }
}
```

Nginx can't verify the JWTs directly, that is part of the reason why in my testing HAProxy is about twice as fast as Nginx (~20ms compared to ~50ms)

## Planned features:
 - Parse custom claims and add them to the cookie
 - Support for refresh tokens
 - Support for JWS
