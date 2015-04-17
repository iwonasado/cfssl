package scan

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cloudflare/cf-tls/tls"
	"github.com/cloudflare/cfssl/helpers"
)

// PKI contains scanners for the Public Key Infrastructure.
var PKI = &Family{
	Description: "Scans for the Public Key Infrastructure",
	Scanners: map[string]*Scanner{
		"CertExpiration": {
			"Host's certificate hasn't expired",
			certExpiration,
		},
		"ChainValidation": {
			"All certificates in host's chain are valid",
			chainValidation,
		},
		"Revocation": {
			"CRL and/or OCSP revocation responses correct",
			revocation,
		},
		"SHA-1": {
			"Checks for any weak SHA-1 hashes in certificate chain",
			chainSHA1,
		},
	},
}

type expiration time.Time

func (e expiration) String() string {
	return time.Time(e).Format("Jan 2 15:04:05 2006 MST")
}

func certExpiration(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	e := helpers.ExpiryTime(conn.ConnectionState().PeerCertificates)
	if e == nil {
		return
	}
	expirationTime := *e
	output = expirationTime

	if time.Now().After(expirationTime) {
		return
	}

	if time.Now().Add(time.Hour * 24 * 30).After(expirationTime) {
		grade = Warning
		return
	}

	grade = Good
	return
}

type certNames []string

func (names certNames) String() string {
	return strings.Join(names, ",")
}

func chainValidation(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	hostname, _, _ := net.SplitHostPort(host)

	if certs[0].VerifyHostname(hostname) != nil {
		err = fmt.Errorf("Couldn't verify hostname %s", hostname)
		return
	}

	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		parent := certs[i+1]
		if !parent.IsCA {
			err = fmt.Errorf("%s is not a CA", parent.Subject.CommonName)
			return
		}

		if !bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId) {
			err = fmt.Errorf("AuthorityKeyId differs from parent SubjectKeyId")
			return
		}

		if err = cert.CheckSignatureFrom(parent); err != nil {
			return
		}
	}
	grade = Good
	return
}

func revocation(host string) (grade Grade, output Output, err error) {

	return
}

func chainSHA1(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		err = errors.New("found no certficates")
		return
	}

	var errs []string

	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		parent := certs[i+1]

		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA1:
			errs = append(errs, fmt.Sprintf("%s is signed by ECDSAWithSHA1", cert.Subject.CommonName))
		case x509.SHA1WithRSA:
			errs = append(errs, fmt.Sprintf("%s is signed by ECDSAWithSHA1", cert.Subject.CommonName))
		}

		if !bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId) {
			err = fmt.Errorf("AuthorityKeyId differs from parent SubjectKeyId")
			return
		}

		if err = cert.CheckSignatureFrom(parent); err != nil {
			return
		}
	}
	if len(errs) == 0 {
		grade = Good
	} else {
		output = outputString(strings.Join(errs, "\n"))
	}
	return
}
