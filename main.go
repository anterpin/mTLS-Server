package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

// must be 16 bytes
const SECRET = "cdslfjlkjsSLDKal"
const nonce = "ciadfjdalkfj"

func setupCertificates() {
	newCA, err := loadCA()
	if err != nil {
		log.Fatal(err)
	}
	certFieldList := []struct {
		name       string
		dir        string
		commonName string
	}{
		{"server", "./cert/", "server"},
		{"client", "./client/cert/", "client 1"},
		{"client1", "./client/cert1/", "client 2"},
	}
	aesCipher, err := aes.NewCipher([]byte(SECRET))
	if err != nil {
		log.Fatal(err)
	}
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatal(err)
	}

	for _, certFields := range certFieldList {
		certFile := fmt.Sprintf("%scert.pem", certFields.dir)
		caCertFile := fmt.Sprintf("%scaCert.pem", certFields.dir)
		keyFile := fmt.Sprintf("%skey.pem", certFields.dir)
		//create server and clients certificates signed by the CA
		if !newCA {
			continue
		}

		cipherText := aesgcm.Seal(nil, []byte(nonce), []byte(certFields.commonName), nil)
		encodedCommonName := base64.StdEncoding.EncodeToString(cipherText)
		_, _, err = createCertificateAndSave(encodedCommonName, certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}
		func() {
			command := exec.Command("cp", "./caCert.pem", caCertFile)
			err := command.Run()
			if err != nil || command.ProcessState.ExitCode() != 0 {
				log.Fatal("cannot copy the cas files")
			}
		}()
	}

}
func setupTLS() *tls.Config {

	setupCertificates()

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384, // the cipher suites are not editable in go 1.16 using TLS 1.3
		},
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}

	return tlsConfig
}

func setupMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		// we are retriving the encrypted client information from the client certificate, similar how jwt would work
		// there is the same question like jwt and stored sessions.
		certs := r.TLS.PeerCertificates
		if len(certs) == 0 {
			http.Error(rw, "no client certificate", http.StatusBadRequest)
			return
		}
		cipherText, err := base64.StdEncoding.DecodeString(certs[0].Subject.CommonName)
		if err != nil {
			http.Error(rw, "common name is not a base64 string", http.StatusBadRequest)
			return
		}

		aesCipher, err := aes.NewCipher([]byte(SECRET))
		if err != nil {
			http.Error(rw, "cannot create the cipher", http.StatusInternalServerError)
			return
		}
		aesgcm, err := cipher.NewGCM(aesCipher)
		if err != nil {
			http.Error(rw, "cannot create the gcm", http.StatusInternalServerError)
			return
		}
		plainText, err := aesgcm.Open(nil, []byte(nonce), cipherText, nil)
		if err != nil {
			http.Error(rw, "cannot decrypt the common name", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(rw, string(plainText))

	})

	return mux
}

func main() {
	PORT, err := strconv.ParseUint(os.Getenv("PORT"), 10, 64)
	if err != nil || PORT > 65535 {
		PORT = 8443
	}
	server := http.Server{
		TLSConfig:    setupTLS(),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      setupMux(),
		Addr:         fmt.Sprintf(":%d", PORT),
	}

	fmt.Println("Server Start")
	log.Fatal(server.ListenAndServeTLS("cert/cert.pem", "cert/key.pem"))
}
