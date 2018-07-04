package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

type CertificateTestSuite struct {
	suite.Suite
}

func (suite *CertificateTestSuite) TestExtractEnhancedRDNSequenceToString() {

	// create a new certificate from the string literal - (doesn't contain extra attribute names)
	commonCert := `-----BEGIN CERTIFICATE-----
MIIC8jCCAdoCCQCdC824csOlXTANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJU
QzELMAkGA1UECAwCVE4xDTALBgNVBAcMBENJVFkxEDAOBgNVBAoMB0NPTVBBTlkw
HhcNMTgwNjA0MDkwMzA5WhcNMTkwNjA0MDkwMzA5WjA7MQswCQYDVQQGEwJUQzEL
MAkGA1UECAwCVE4xDTALBgNVBAcMBENJVFkxEDAOBgNVBAoMB0NPTVBBTlkwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYahRnf7gxkjz81VX9JjQ/PiB7
UpGInckBCl5mah/Q3ucr3OvaLLdO4pfmAMTanLxgcTsP7k/yyvZF17IMhQ5wpNzn
zfLlAswQT6sqkNyJUx1MXI5mjAiDDMpUh0c9CnGaZa/LrnTXmQhsv8uzLDPUYb37
iHHjP7isYiG+7YE2CpRwHazj0SYba4HAYw8Z1L8Z6kI1gfdIiqI5DFMBdmQlac3P
YCtYytQd3swCsxf57/M9X+Ct7DVcuPKmR5vv4ONL2YBwtvULX8DA8aApdxIrHCZE
NRaaCUmMSo4JXHbY5CVP6AXdo3Iz+3v485qtF8lk+XU/fQGNTdgs1hmsTNMRAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAAyvW6yVbfCLMxuQ1Nt61OmKA96fTtdTpLuI
nq9C0XVoFqgrEeobxdH4QbwxduRHWpHEuFskJCBnMbX0d8v63KEN/6I0Ub4niaeP
nvykp3uoKrRwIZo4OxJFuuuLuUw3aAwkKeqsy5HZsKqi9QscHExRKbcIdlkgxzRW
IEPEGk7acMlT20ECjc4zbdza8PKQeBeEVLINJVMRGPZIlo/6z6BxSnINQiWBk1WZ
lXTmJMXGB7/0ECDz2JT1Mbs/q2ijlZywz0xsp+Zdsp1I01wvwqw5M12PHf3buM1w
SoPmZKiBeb+2OQ2n7+FI8ftkqxWw6zjh651brAoy/0zqLTRPh+c=
-----END CERTIFICATE-----
`

	// tests the case where the certificate doesn't contain extra attributes names
	var crt *x509.Certificate

	crt = ParseCert(commonCert)

	ers := ExtractEnhancedRDNSequenceToString(crt)

	// add some extra attribute names to the certificate
	obj := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	extraAttributeValue1 := pkix.AttributeTypeAndValue{Type: obj, Value: "v1"}
	extraAttributeValue2 := pkix.AttributeTypeAndValue{Type: obj, Value: "v2"}
	enhancedCert := crt
	enhancedCert.Subject.Names = append(enhancedCert.Subject.Names, extraAttributeValue1, extraAttributeValue2)
	ers2 := ExtractEnhancedRDNSequenceToString(enhancedCert)

	suite.Equal("O=COMPANY,L=CITY,ST=TN,C=TC", ers)
	suite.Equal("O=COMPANY,L=CITY,ST=TN,C=TC,DC=v2,DC=v1", ers2)
}

func (suite *CertificateTestSuite) TestCertHasExpired() {

	commonCert := `-----BEGIN CERTIFICATE-----
MIIC8jCCAdoCCQCdC824csOlXTANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJU
QzELMAkGA1UECAwCVE4xDTALBgNVBAcMBENJVFkxEDAOBgNVBAoMB0NPTVBBTlkw
HhcNMTgwNjA0MDkwMzA5WhcNMTkwNjA0MDkwMzA5WjA7MQswCQYDVQQGEwJUQzEL
MAkGA1UECAwCVE4xDTALBgNVBAcMBENJVFkxEDAOBgNVBAoMB0NPTVBBTlkwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYahRnf7gxkjz81VX9JjQ/PiB7
UpGInckBCl5mah/Q3ucr3OvaLLdO4pfmAMTanLxgcTsP7k/yyvZF17IMhQ5wpNzn
zfLlAswQT6sqkNyJUx1MXI5mjAiDDMpUh0c9CnGaZa/LrnTXmQhsv8uzLDPUYb37
iHHjP7isYiG+7YE2CpRwHazj0SYba4HAYw8Z1L8Z6kI1gfdIiqI5DFMBdmQlac3P
YCtYytQd3swCsxf57/M9X+Ct7DVcuPKmR5vv4ONL2YBwtvULX8DA8aApdxIrHCZE
NRaaCUmMSo4JXHbY5CVP6AXdo3Iz+3v485qtF8lk+XU/fQGNTdgs1hmsTNMRAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAAyvW6yVbfCLMxuQ1Nt61OmKA96fTtdTpLuI
nq9C0XVoFqgrEeobxdH4QbwxduRHWpHEuFskJCBnMbX0d8v63KEN/6I0Ub4niaeP
nvykp3uoKrRwIZo4OxJFuuuLuUw3aAwkKeqsy5HZsKqi9QscHExRKbcIdlkgxzRW
IEPEGk7acMlT20ECjc4zbdza8PKQeBeEVLINJVMRGPZIlo/6z6BxSnINQiWBk1WZ
lXTmJMXGB7/0ECDz2JT1Mbs/q2ijlZywz0xsp+Zdsp1I01wvwqw5M12PHf3buM1w
SoPmZKiBeb+2OQ2n7+FI8ftkqxWw6zjh651brAoy/0zqLTRPh+c=
-----END CERTIFICATE-----
`

	// tests the case where the certificate doesn't contain extra attributes names
	var crt *x509.Certificate

	crt = ParseCert(commonCert)

	// test the normal case
	// cert has 365 days activation span , so the test will fail after a year, thus we just make the expiration date something in the future that will never be reached
	crt.NotAfter = time.Now().Add(time.Hour * 24)
	err1 := CertHasExpired(crt)

	// expired case
	crt.NotAfter = time.Now()
	err2 := CertHasExpired(crt)

	//  not active yet
	crt = ParseCert(commonCert)
	// move the not before date a day to the future so the check fails because we haven't reached that date yet
	crt.NotBefore = time.Now().Add(time.Hour * 24)
	err3 := CertHasExpired(crt)

	suite.Nil(err1)
	suite.Equal("Your certificate has expired", err2.Error())
	suite.Equal("Your certificate is not active yet", err3.Error())
}

func (suite *CertificateTestSuite) TestValidateClientCertificate() {

	commonCert := `-----BEGIN CERTIFICATE-----
MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy
MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh
bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh
bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0
Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6
ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51
UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n
c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY
MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz
30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG
BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv
bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB
AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E
T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v
ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p
mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/
e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps
P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY
dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc
2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG
V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4
HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX
j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII
0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap
lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf
+AZxAeKCINT+b72x
-----END CERTIFICATE-----`

	var crt *x509.Certificate

	// normal case
	crt = ParseCert(commonCert)
	crt.Subject.CommonName = "localhost"

	err1 := ValidateClientCertificate(crt, "127.0.0.1:8080")

	suite.Nil(err1)

	// mismatch
	crt = ParseCert(commonCert)
	err2 := ValidateClientCertificate(crt, "127.0.0.1:8080")
	suite.Equal("x509: certificate is valid for COMODO RSA Domain Validation Secure Server CA, not localhost", err2.Error())

	// mismatch
	crt = ParseCert(commonCert)
	crt.Subject.CommonName = ""
	err3 := ValidateClientCertificate(crt, "127.0.0.1:8080")
	suite.Equal("x509: certificate is not valid for any names, but wanted to match localhost", err3.Error())

	//mismatch
	crt = ParseCert(commonCert)
	crt.DNSNames = []string{"COMODO RSA Domain Validation Secure Server CA"}
	obj := asn1.ObjectIdentifier{2, 5, 29, 17}
	e1 := pkix.Extension{Id: obj, Critical: false, Value: []byte("")}
	crt.Extensions = append(crt.Extensions, e1)
	err4 := ValidateClientCertificate(crt, "127.0.0.1:8080")
	suite.Equal("x509: certificate is valid for COMODO RSA Domain Validation Secure Server CA, not localhost", err4.Error())

}

func TestCertificateTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateTestSuite))
}
