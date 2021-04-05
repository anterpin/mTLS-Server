package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	PORT, err := strconv.ParseUint(os.Getenv("PORT"), 10, 16)
	if err != nil || PORT > 65535 {
		PORT = 8443
	}

	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "cert"
	}

	cert, err := tls.LoadX509KeyPair(certDir+"/cert.pem", certDir+"/key.pem")
	if err != nil {
		log.Fatal(err)
	}

	caCertBytes, err := ioutil.ReadFile(certDir + "/caCert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCertBytes)
	if !ok {
		log.Fatal("cannot load ca certificate from pem")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://localhost:%d", PORT))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}
