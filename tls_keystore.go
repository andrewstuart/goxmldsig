package dsig

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

//Well-known errors
var (
	ErrNonRSAKey           = fmt.Errorf("Private key was not RSA")
	ErrMissingCertificates = fmt.Errorf("No public certificates provided")
)

//TLSCertKeyStore wraps the stdlib tls.Certificate to return its contained key
//and certs.
type TLSCertKeyStore tls.Certificate

//GetKeyPair implements X509KeyStore using the underlying tls.Certificate
func (t TLSCertKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	pk, ok := t.PrivateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, nil, ErrNonRSAKey
	}

	if len(t.Certificate) < 1 {
		return nil, nil, ErrMissingCertificates
	}

	crt := t.Certificate[0]

	return pk, crt, nil
}

// Certificates implements x509CertificateStore
func (t TLSCertKeyStore) Certificates() (roots []*x509.Certificate, err error) {
	if t.Leaf == nil {
		crt, err := x509.ParseCertificate(t.Certificate[0])
		if err != nil {
			return nil, err
		}
		t.Leaf = crt
	}
	return []*x509.Certificate{t.Leaf}, nil
}
