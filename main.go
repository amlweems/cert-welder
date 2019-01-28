package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/crypto/pkcs7"
)

// ParseOneCertificateFromPEM attempts to parse one PEM encoded certificate object,
// either a raw x509 certificate or a PKCS #7 structure possibly containing
// multiple certificates, from the top of certsPEM, which itself may
// contain multiple PEM encoded certificate objects.
func ParseOneCertificateFromPEM(certsPEM []byte) ([]*x509.Certificate, []byte, error) {
	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		pkcs7data, err := pkcs7.ParsePKCS7(block.Bytes)
		if err != nil {
			return nil, rest, err
		}
		if pkcs7data.ContentInfo != "SignedData" {
			return nil, rest, errors.New("only PKCS #7 Signed Data Content Info supported for certificate parsing")
		}
		certs := pkcs7data.Content.SignedData.Certificates
		if certs == nil {
			return nil, rest, errors.New("PKCS #7 structure contains no certificates")
		}
		return certs, rest, nil
	}
	var certs = []*x509.Certificate{cert}
	return certs, rest, nil
}

// ParseCertificatesPEM parses a sequence of PEM-encoded certificate and returns them,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatesPEM(certsPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	certsPEM = bytes.TrimSpace(certsPEM)
	for len(certsPEM) > 0 {
		var cert []*x509.Certificate
		cert, certsPEM, err = ParseOneCertificateFromPEM(certsPEM)
		if err != nil {
			return nil, err
		} else if cert == nil {
			break
		}

		certs = append(certs, cert...)
	}
	if len(certsPEM) > 0 {
		return nil, err
	}
	return certs, nil
}

var sentinel = []byte("-----BEGIN CERTIFICATE-----")

func likelyCert(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	buf := make([]byte, 512)
	_, err = f.Read(buf)
	if err != nil {
		return false
	}
	return bytes.Contains(buf, sentinel)
}

type Pool struct {
	bySPKI map[string]int
	paths  map[string][]string
	certs  []*x509.Certificate
}

func NewCertPool() *Pool {
	return &Pool{
		bySPKI: make(map[string]int),
		paths:  make(map[string][]string),
	}
}

func (s *Pool) AddCert(path string, cert *x509.Certificate) {
	spki := Fingerprint(cert)

	s.paths[spki] = append(s.paths[spki], path)
	if _, ok := s.bySPKI[spki]; !ok {
		s.bySPKI[spki] = len(s.certs)
		s.certs = append(s.certs, cert)
	}
}

func Fingerprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%x", h.Sum(nil))
}

type Node struct {
	Id       string
	Paths    []string
	Cert     *x509.Certificate
	Parent   *Node
	Children []*Node
}

func (n *Node) Print(indent int) {
	spacer := strings.Repeat("    ", indent)
	fmt.Printf("%s[%s]\n", spacer, n.Cert.Subject)
	for _, path := range n.Paths {
		fmt.Printf("  %s%s\n", spacer, path)
	}
	for _, c := range n.Children {
		c.Print(indent + 1)
	}
}

func main() {
	pool := NewCertPool()

	err := filepath.Walk(".",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !likelyCert(path) {
				return nil
			}
			buf, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}
			certs, err := ParseCertificatesPEM(buf)
			if err != nil {
				return nil
			}
			for _, cert := range certs {
				pool.AddCert(path, cert)
			}

			return nil
		})
	if err != nil {
		log.Println(err)
	}

	nodes := make(map[string]*Node)
	for spki, i := range pool.bySPKI {
		nodes[spki] = &Node{
			Id:    spki,
			Paths: pool.paths[spki],
			Cert:  pool.certs[i],
		}
	}
	for a, c := range nodes {
		for b, p := range nodes {
			if a == b {
				continue
			}
			if c.Cert.CheckSignatureFrom(p.Cert) == nil {
				p.Children = append(p.Children, c)
				c.Parent = p
			}
		}
	}

	for _, n := range nodes {
		if len(n.Children) > 0 {
			n.Print(0)
		}
	}
}
