# Auth Encrypt

Allows accessing encrypted files over the web by decrypting them through `openssl`.

The cipher used is ChaCha2 with PBKDF2, where the key is the base-64 encoding of the username and password joined by a colon (the value of the token for HTTP basic authentication).
Here's how to encrypt a file such that it can be decrypted by the server:

```shell
openssl enc -e -pbkdf2 -chacha20 -k "$(echo -n 'username:password' | base64)" < plain.txt > encrypted.txt
```

Note that the server has absolutely no notion of whether a file is encrypted or not, and will blindly try to decrypt any file within its working directory if requested to do so. Usually this will cause an OpenSSL error which is reported as a 500 error code in the HTTP response. Wrong passwords are also not detected, and will result in garbage decrypted output.
