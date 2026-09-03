// Package certgen ports pythonoperator/src/myceliam/certgen.py: generating a
// self-signed RSA keypair/certificate for signedjwt clients that have no
// pre-existing <sa-name>-oidc-credentials secret to read a cert from.
package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateSelfSignedKeypair generates an RSA keypair and a self-signed X.509
// certificate wrapping the public key. Returns (certPEM, keyPEM).
func GenerateSelfSignedKeypair(commonName string, keySize, validDays int) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("generating RSA key: %w", err)
	}

	// 128-bit serial, same magnitude as x509.random_serial_number()'s 20 bytes.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now().UTC()
	name := pkix.Name{CommonName: commonName}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      name,
		Issuer:       name,
		NotBefore:    now,
		NotAfter:     now.Add(time.Duration(validDays) * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating self-signed certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
