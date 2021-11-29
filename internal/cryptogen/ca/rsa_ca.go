package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"

	//"crypto"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	//"crypto/rand"
	//"crypto/sha256"
	"crypto/x509"
	//"crypto/x509/pkix"
	//"encoding/pem"
	//"io/ioutil"
	//"math/big"
	//"net"
	"os"
	//"path/filepath"
	//"strings"
	//"time"

	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	//"github.com/pkg/errors"
)

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewRSACA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) (*CA, error) {

	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		return nil, err
	}

	priv, err := csp.GenerateRSAPrivateKey(baseDir)
	res,_ := json.Marshal(priv)
	fmt.Println("priv : ",string(res))
	if err != nil {
		return nil, err
	}

	template := x509Template()
	//this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}

	//set the organization for the subject
	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = computeRSASKI(priv)

	x509Cert, err := genCertificateRSA(
		baseDir,
		name,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return nil, err
	}
	ca = &CA{
		Name:               name,
		Signer:             priv,
		SignCert:           x509Cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}

	return ca, err
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKeyASN struct {
	N *big.Int
	E int
}
// compute Subject Key Identifier using RFC 7093, Section 2, Method 4
func computeRSASKI(privKey *rsa.PrivateKey) []byte {
	if privKey == nil {
		return nil
	}

	// Marshall the public key
	raw, _ := asn1.Marshal(rsaPublicKeyASN{
		N: privKey.N,
		E: privKey.E,
	})

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// generate a signed X509 certificate using RSA
func genCertificateRSA(
	baseDir,
	name string,
	template,
	parent *x509.Certificate,
	pub *rsa.PublicKey,
	priv interface{},
) (*x509.Certificate, error) {

	//create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}
