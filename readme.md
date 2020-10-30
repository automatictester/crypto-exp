### OpenSSL

Inspect X509 certificate:

```
openssl x509 -text -noout -in cert.pem
```

Extract public key from X509 certificate:

```
openssl x509 -pubkey -noout -in cert.pem
```

Inspect RSA private key:

```
openssl rsa -text -noout -in rsa
```

Extract RSA public key from private key:

```
openssl rsa -pubout -in rsa -out rsa.pub
```

Inspect RSA public key:

```
openssl rsa -pubin -text -noout -in rsa.pub
```
