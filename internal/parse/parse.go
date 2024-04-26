package parse

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// CertificateData struct contains base64 pem data
type CertificateData struct {
	SecretName    string
	Namespace     string
	Type          string
	Certificate   string
	CaCertificate string
	SecretKeys    []string
}

// ParsedCertificateData struct contains decoded x509 certificates
type ParsedCertificateData struct {
	SecretName    string
	Namespace     string
	Certificate   *x509.Certificate
	CaCertificate *x509.Certificate
}

// NewCertificateData takes secret data and extracts base64 pem strings
// nolint gocognit
func NewCertificateData(ns, secretName string, data map[string]interface{}, secretKey string, listKeys, showCa bool) (*CertificateData, []string, error) {
	_, ok := data["data"]
	var keysList []string
	returnCertPemKey := "tls.crt"
	returnCaPemKey := "ca.crt"
	if !ok {
		return nil, nil, nil
	}
	certsMap := data["data"].(map[string]interface{})

	certData := CertificateData{
		SecretName: secretName,
		Namespace:  ns,
	}

	if secretKey != "" {
		if val, ok := certsMap[secretKey]; ok {
			certData.Certificate = fmt.Sprintf("%v", val)
		}

		return &certData, nil, nil
	}

	secretType := fmt.Sprintf("%v", data["type"])

	secretCrtPemKeyList := strings.Split(os.Getenv("CRT_PEM_KEY_LIST"), ",")
	secretCaPemKeyList := strings.Split(os.Getenv("CA_PEM_KEY_LIST"), ",")
	// nolint gosec
	if secretType == "kubernetes.io/tls" ||
		secretType == "Opaque" {
		if val, ok := certsMap["tls.crt"]; ok {
			certData.Certificate = fmt.Sprintf("%v", val)
		} else {
			for _, crtPemKey := range secretCrtPemKeyList {
				if val, ok := certsMap[crtPemKey]; ok {
					certData.Certificate = fmt.Sprintf("%v", val)
					returnCertPemKey = crtPemKey
					break
				}
			}
		}
		if showCa {
			if val, ok := certsMap["ca.crt"]; ok {
				certData.CaCertificate = fmt.Sprintf("%v", val)
			} else {
				for _, caPemKey := range secretCaPemKeyList {
					if val, ok := certsMap[caPemKey]; ok {
						certData.CaCertificate = fmt.Sprintf("%v", val)
						returnCaPemKey = caPemKey
						break
					}
				}
			}
		}
		keysList = append(keysList, returnCertPemKey, returnCaPemKey)
		certData.Type = secretType
		return &certData, keysList, nil
	}

	if listKeys && certsMap != nil && len(certsMap) > 0 {
		certData.SecretKeys = make([]string, len(certsMap))
		i := 0

		for key := range certsMap {
			certData.SecretKeys[i] = key
			i++
		}

		return &certData, nil, nil
	}

	return nil, nil, fmt.Errorf("unsupported secret type %s", secretType)
}

// ParseCertificates method parses each base64 pem strings and creates x509 certificates
func (c *CertificateData) ParseCertificates() (*ParsedCertificateData, error) {
	var cert *x509.Certificate
	var err error

	if c.Certificate != "" {
		cert, err = parse(c.Certificate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate %w", err)
		}
	}

	var caCert *x509.Certificate
	if c.CaCertificate != "" {
		caCert, err = parse(c.CaCertificate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ca certificate %w", err)
		}
	}

	result := ParsedCertificateData{
		SecretName:    c.SecretName,
		Namespace:     c.Namespace,
		Certificate:   cert,
		CaCertificate: caCert,
	}

	return &result, nil
}

func parse(base64Pem string) (*x509.Certificate, error) {
	decodedPemCertificate, err := base64.StdEncoding.DecodeString(base64Pem)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode %w", err)
	}

	block, _ := pem.Decode(decodedPemCertificate)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error %w", err)
	}

	return certificate, nil
}
