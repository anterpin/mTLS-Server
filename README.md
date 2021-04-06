# mTLS Server with CA generating client's certificates

It's a brief project in go which demonstate the use of a server CA that sign client certificates. </br> The client certificates could be generated at runtime and then used in the mTLS authentication with the server.

For the authorization it stores AES encrypted and encoded token in the certificate Common Name for later use.

# Usage
The server authomatcally generates the CA and the certificates.  
To start the server just: `go run main.go ca.go`  
To run the client just: `go run main.go`  
You can set some environment variables such as CERT_DIR and PORT.
