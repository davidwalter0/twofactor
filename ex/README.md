##### Example twofactor library use

- main.go is a simple create a qr code based on the comments from the library author
- server.go runs a secure https/tls server that requires certificates


```
    # Replace example.com with your issuer
    # Use tls/configured service with letsencrypt certs
    export APP_HTTPS=true
    export APP_HOST=example.com
    export APP_PORT=8443
    export APP_CERT=/etc/letsencrypt/live/example.com/cert.pem
    export APP_KEY=/etc/letsencrypt/live/example.com/privkey.pem
    sudo -E /usr/local/go/bin/go run serve.go

```

---
Test with curl or write a front end application

Fetch a qrcode add it to google auth and insert the token(pin) in the next command
```
curl -k 'https://example.com:8443/?account=uid@example.com&issuer=example.com
```


Validate the token against the server
```
curl -k 'https://example.com:8443/validate/?account=uid@example.com&issuer=example.com&token=937052'
```

