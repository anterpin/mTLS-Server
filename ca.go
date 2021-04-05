package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"sync"
	"time"
)

var caCert *x509.Certificate
var caPrivKey *rsa.PrivateKey
var caMutex sync.Mutex

func loadCertAndKey(certFile string, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, nil, errors.New("cannot decode pem certficate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	kbytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	kblock, _ := pem.Decode(kbytes)
	if kblock == nil {
		return nil, nil, errors.New("cannot decode pem private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey, nil
}

func loadCA() (error, bool) {

	newCA := false
	cert, key, err := loadCertAndKey("caCert.pem", "caKey.pem")
	if err != nil {
		newCA = true
		cert, key, err = createCA()
		if err != nil {
			return err, newCA
		}
		caMutex.Lock()
		err = saveCertificateAndKey(cert, cert, key, key, "caCert.pem", "caKey.pem")
		caMutex.Unlock()
		if err != nil {
			return err, newCA
		}
	}
	caMutex.Lock()

	caCert = cert
	caPrivKey = key
	caMutex.Unlock()

	return nil, newCA
}

func saveCertificateAndKey(caCert *x509.Certificate, cert *x509.Certificate, caPrivKey *rsa.PrivateKey, key *rsa.PrivateKey, certFile string, keyFile string) error {
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
	certPEM := &bytes.Buffer{}
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyPEM := &bytes.Buffer{}
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	err = ioutil.WriteFile(certFile, certPEM.Bytes(), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(keyFile, keyPEM.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func createCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		DNSNames:     []string{"localhost"},
		Subject: pkix.Name{
			Organization:  []string{"Anto INC."},
			Country:       []string{"IT"},
			Province:      []string{""},
			Locality:      []string{"Brescia"},
			StreetAddress: []string{"test"},
			PostalCode:    []string{"...."},
			CommonName:    "anto inc",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	const KEY_SIZE = 2048
	caPrivKey, err := rsa.GenerateKey(rand.Reader, KEY_SIZE)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivKey, nil
}

func createCertificate(commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		DNSNames:     []string{"localhost"},
		Subject: pkix.Name{
			Organization:  []string{"Anto INC."},
			Country:       []string{"IT"},
			Province:      []string{""},
			Locality:      []string{"Brescia"},
			StreetAddress: []string{"test"},
			PostalCode:    []string{"...."},
			CommonName:    commonName,
		},
		// IP field maybe is not needed
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	const KEY_SIZE = 2048
	certPrivKey, err := rsa.GenerateKey(rand.Reader, KEY_SIZE)
	if err != nil {
		return nil, nil, err
	}

	return cert, certPrivKey, nil
}

func createCertificateAndSave(commonName string, certFile string, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, key, err := createCertificate(commonName)
	if err != nil {
		return nil, nil, err
	}
	err = saveCertificateAndKey(caCert, cert, caPrivKey, key, certFile, keyFile)

	return cert, key, err
}
