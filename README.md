# mTLS Server with CA generating client's certificates

It's a brief project in go which demonstate the use of a server CA that sign client's certificates. </br> The client's certificates could be generated at runtime and then used in the mTLS authentication with the server.

For the authorization it stores aes encrypted and encoded token in the certificate Common Name for later use.
