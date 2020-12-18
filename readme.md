### OpenSSL

Inspect X509 certificate:

```
openssl x509 -in cert.pem -text -noout
openssl x509 -in cert.der -inform der -text -noout
```

Convert certificate from PEM to DER:

```
openssl x509 -in cert.pem -outform der -out cert.der
```

Extract public key from X509 certificate:

```
openssl x509 -in cert.pem -pubkey -noout
```

Inspect RSA public key:

```
openssl rsa -in rsa.pub -pubin -text -noout
```

Inspect RSA private key:

```
openssl rsa -in rsa -text -noout
```

Extract RSA public key from private key:

```
openssl rsa -in rsa -pubout -out rsa.pub
```

Download website certificate:

```
echo "" | openssl s_client -connect google.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > cert.pem
```
