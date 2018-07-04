package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/ARGOeu/argo-api-authn/auth-methods"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/gorilla/mux"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"

	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"
)

type CertificateHandlerSuite struct {
	suite.Suite
}

// MockServiceTypeEndpoint mocks the behavior of a service type endpoint and returns a response containing the requested resource
func MockServiceTypeEndpoint(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("{\"token\": \"some-value\"}"))
}

func AuthViaCertSetUp(reqPath string) (*http.Request, *stores.Mockstore, *config.Config, error) {

	var err error
	var crt *x509.Certificate
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	// create a new certificate from the string literal
	cert := `-----BEGIN CERTIFICATE-----
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
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	if crt, err = x509.ParseCertificate(block.Bytes); err != nil {
		LOGGER.Error(err.Error())
		return req, mockstore, cfg, err
	}

	// avoid expiration
	crt.NotAfter = time.Now().Add(time.Hour * 24)
	crt.IPAddresses = append(crt.IPAddresses, net.ParseIP("192.168.62.20"))

	// create a new request and add the created certificate
	if req, err = http.NewRequest("GET", reqPath, nil); err != nil {
		return req, mockstore, cfg, err
	}

	req.TLS = &tls.ConnectionState{}
	req.TLS.PeerCertificates = append(req.TLS.PeerCertificates, crt)
	req.RemoteAddr = "127.0.0.1:8080"
	req.TLS.PeerCertificates[0].Subject.CommonName = "localhost"

	// set up the mockstore
	mockstore = &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()
	// append a service type to be used only in auth via cert tests
	qSt := stores.QServiceType{Name: "s_auth_cert", Hosts: []string{"h1_auth_cert"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "mock-api-key", UUID: "uuid_auth_cert", CreatedOn: "2018-05-05T18:04:05Z"}
	qSt2 := stores.QServiceType{Name: "s_auth_cert_incorrect", Hosts: []string{"h1_auth_cert"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "mock-api-key", UUID: "uuid_auth_cert_incorrect", CreatedOn: "2018-05-05T18:04:05Z"}
	mockstore.ServiceTypes = append(mockstore.ServiceTypes, qSt, qSt2)
	// append a binding to be used only in auth via cert tests
	qB := stores.QBinding{Name: "b_auth_cert", ServiceUUID: "uuid_auth_cert", Host: "h1_auth_cert", DN: "CN=localhost,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	qB2 := stores.QBinding{Name: "b_auth_cert_incorrect", ServiceUUID: "uuid_auth_cert_incorrect", Host: "h1_auth_cert", DN: "CN=localhost,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	mockstore.Bindings = append(mockstore.Bindings, qB, qB2)

	// set up cfg
	cfg = &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	// add a mock auth method handler
	auth_methods.AuthMethodHandlers["mock-api-key"] =
		func(data map[string]interface{}, store stores.Store, config *config.Config) (*http.Response, error) {

			var req2 *http.Request
			var err error

			// mock the request that will take place against the given service type
			if req2, err = http.NewRequest("GET", "http://localhost:8080/some_endpoint", nil); err != nil {
				LOGGER.Error(err.Error())
			}
			router := mux.NewRouter().StrictSlash(true)
			w := httptest.NewRecorder()
			router.HandleFunc("/some_endpoint", MockServiceTypeEndpoint)
			router.ServeHTTP(w, req2)
			return w.Result(), err
		}

	return req, mockstore, cfg, err
}

// TestAuthViaCert tests the normal case
func (suite *CertificateHandlerSuite) TestAuthViaCert() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "token": "some-value"
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertNoCRLDPs tests the case where the certificate has no crl distribution points on it
func (suite *CertificateHandlerSuite) TestAuthViaCertNoCRLDPs() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Your certificate is invalid. No CRLDistributionPoints found on the certificate",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	// empty the slice
	req.TLS.PeerCertificates[0].CRLDistributionPoints = []string{}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertRevoked tests case of a revoked cert
func (suite *CertificateHandlerSuite) TestAuthViaCertRevoked() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request
	var crt *x509.Certificate

	// 2014/05/22 14:18:31 Serial number match: intermediate is revoked.
	//	2014/05/22 14:18:31 certificate is revoked via CRL
	// 2014/05/22 14:18:31 Revoked certificate: misc/intermediate_ca/MobileArmorEnterpriseCA.crt
	var revokedCert = `-----BEGIN CERTIFICATE-----
MIIEEzCCAvugAwIBAgILBAAAAAABGMGjftYwDQYJKoZIhvcNAQEFBQAwcTEoMCYG
A1UEAxMfR2xvYmFsU2lnbiBSb290U2lnbiBQYXJ0bmVycyBDQTEdMBsGA1UECxMU
Um9vdFNpZ24gUGFydG5lcnMgQ0ExGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
CzAJBgNVBAYTAkJFMB4XDTA4MDMxODEyMDAwMFoXDTE4MDMxODEyMDAwMFowJTEj
MCEGA1UEAxMaTW9iaWxlIEFybW9yIEVudGVycHJpc2UgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCaEjeDR73jSZVlacRn5bc5VIPdyouHvGIBUxyS
C6483HgoDlWrWlkEndUYFjRPiQqJFthdJxfglykXD+btHixMIYbz/6eb7hRTdT9w
HKsfH+wTBIdb5AZiNjkg3QcCET5HfanJhpREjZWP513jM/GSrG3VwD6X5yttCIH1
NFTDAr7aqpW/UPw4gcPfkwS92HPdIkb2DYnsqRrnKyNValVItkxJiotQ1HOO3YfX
ivGrHIbJdWYg0rZnkPOgYF0d+aIA4ZfwvdW48+r/cxvLevieuKj5CTBZZ8XrFt8r
JTZhZljbZvnvq/t6ZIzlwOj082f+lTssr1fJ3JsIPnG2lmgTAgMBAAGjgfcwgfQw
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFIZw
ns4uzXdLX6xDRXUzFgZxWM7oME0GA1UdIARGMEQwQgYJKwYBBAGgMgE8MDUwMwYI
KwYBBQUHAgIwJxolaHR0cDovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5
LzA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L1Jv
b3RTaWduUGFydG5lcnMuY3JsMB8GA1UdIwQYMBaAFFaE7LVxpedj2NtRBNb65vBI
UknOMA0GCSqGSIb3DQEBBQUAA4IBAQBZvf+2xUJE0ekxuNk30kPDj+5u9oI3jZyM
wvhKcs7AuRAbcxPtSOnVGNYl8By7DPvPun+U3Yci8540y143RgD+kz3jxIBaoW/o
c4+X61v6DBUtcBPEt+KkV6HIsZ61SZmc/Y1I2eoeEt6JYoLjEZMDLLvc1cK/+wpg
dUZSK4O9kjvIXqvsqIOlkmh/6puSugTNao2A7EIQr8ut0ZmzKzMyZ0BuQhJDnAPd
Kz5vh+5tmytUPKA8hUgmLWe94lMb7Uqq2wgZKsqun5DAWleKu81w7wEcOrjiiB+x
jeBHq7OnpWm+ccTOPCE6H4ZN4wWVS7biEBUdop/8HgXBPQHWAdjL
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(revokedCert))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	if crt, err = x509.ParseCertificate(block.Bytes); err != nil {
		LOGGER.Error(err.Error())

	}

	// avoid expiration
	crt.NotAfter = time.Now().Add(time.Hour * 24)
	crt.IPAddresses = append(crt.IPAddresses, net.ParseIP("192.168.62.20"))
	crt.Subject.CommonName = "localhost"

	expRespJSON := `{
 "error": {
  "message": "Your certificate has been revoked",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	// add to the request the revoked cert
	req.TLS.PeerCertificates[0] = crt
	req.Host = "Mobile Armor Enterprise CA:8080"

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertExpired tests case of an expired certificate
func (suite *CertificateHandlerSuite) TestAuthViaCertExpired() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Your certificate has expired",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	// modify expiration time to be exactly right now so it fails in the future test
	req.TLS.PeerCertificates[0].NotAfter = time.Now()

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertNotActiveYet tests the case of an inactive certificate
func (suite *CertificateHandlerSuite) TestAuthViaCertNotActiveYet() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Your certificate is not active yet",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	// modify date to be in the next day so it fails the shortly after check
	req.TLS.PeerCertificates[0].NotBefore = time.Now().Add(time.Hour * 24)

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertInvalidIp tests the case where the request's dns name doesn't match the cert's  dnsnames
func (suite *CertificateHandlerSuite) TestAuthViaCertInvalidDNSNames() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "x509: certificate is valid for COMODO RSA Domain Validation Secure Server CA, not localhost",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	req.TLS.PeerCertificates[0].DNSNames = []string{"COMODO RSA Domain Validation Secure Server CA"}
	obj := asn1.ObjectIdentifier{2, 5, 29, 17}
	e1 := pkix.Extension{Id: obj, Critical: false, Value: []byte("")}
	req.TLS.PeerCertificates[0].Extensions = append(req.TLS.PeerCertificates[0].Extensions, e1)

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertInvalidIp tests the case where the request's host doesn't match the certificate's CN
func (suite *CertificateHandlerSuite) TestAuthViaCertInvalidHost() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "x509: certificate is valid for COMODO RSA Domain Validation Secure Server CA, not localhost",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	req.TLS.PeerCertificates[0].Subject.CommonName = "COMODO RSA Domain Validation Secure Server CA"

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertNoNames
func (suite *CertificateHandlerSuite) TestAuthViaCertNoNames() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "x509: certificate is not valid for any names, but wanted to match localhost",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	req.TLS.PeerCertificates[0].Subject.CommonName = ""
	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(403, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertValidSubjectCommonName tests the case where the request's cert CN matches with the hostname
func (suite *CertificateHandlerSuite) TestAuthViaCertValidSubjectCommonName() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "token": "some-value"
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	req.TLS.PeerCertificates[0].IPAddresses = []net.IP{}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertUnknownServiceType tests the case where the provided service type is unknown
func (suite *CertificateHandlerSuite) TestAuthViaCertUnknownServiceType() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/unknown/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertUnknownHost tests the case where the provided host is unknown
func (suite *CertificateHandlerSuite) TestAuthViaCertUnknownHost() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/unknown:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthViaCertUnknownDN tests the case where the provided certificate's dn is not assigned to any binding
func (suite *CertificateHandlerSuite) TestAuthViaCertUnknownDN() {

	var err error
	var mockstore *stores.Mockstore
	var cfg *config.Config
	var req *http.Request

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	if req, mockstore, cfg, err = AuthViaCertSetUp("http://localhost:8080/service-types/s_auth_cert/hosts/h1_auth_cert:authX509"); err != nil {
		LOGGER.Error(err.Error())
	}

	// empty the mockstore, so no dn will match
	mockstore.Bindings = []stores.QBinding{}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}:authX509", WrapConfig(DeprecatedAuthViaCert, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

func TestAuthViaCert(t *testing.T) {
	suite.Run(t, new(CertificateHandlerSuite))
}
