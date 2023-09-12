package config

import (
	"testing"

	"crypto/tls"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) TestWithDefaults() {
	cfg := WithDefaults()
	suite.Equal(5, cfg.ServerReadTimeout)
	suite.Equal(5, cfg.ServerHeaderReadTimeout)
	suite.Equal(15, cfg.ServerWriteTimeout)
	suite.Equal(60, cfg.ServerIdleTimeout)
}

func (suite *ConfigTestSuite) TestConfigSetUp() {

	// tests the case of a wrong path to a config file
	cfg1 := &Config{}
	err1 := cfg1.ConfigSetUp("/wrong/path")

	// tests the case of a normal setup
	cfg2 := WithDefaults()
	suite.Equal(5, cfg2.ServerReadTimeout)
	suite.Equal(5, cfg2.ServerHeaderReadTimeout)
	suite.Equal(15, cfg2.ServerWriteTimeout)
	suite.Equal(60, cfg2.ServerIdleTimeout)
	err2 := cfg2.ConfigSetUp("./configuration-test-files/test-conf.json")
	expCfg2 := &Config{
		ServicePort:            9000,
		MongoHost:              "test_mongo_host",
		MongoDB:                "test_mongo_db",
		CertificateAuthorities: "/path/to/cas",
		Certificate:            "/path/to/cert",
		CertificateKey:         "/path/to/key",
		ServiceToken:           "token",
		SupportedAuthTypes:     []string{"x509", "oidc"},
		SupportedAuthMethods:   []string{"api-key", "headers"},
		SupportedServiceTypes:  []string{"ams", "web-api", "custom"},
		VerifySSL:              false,
		TrustUnknownCAs:        false,
		VerifyCertificate:      true,
		ServiceTypesPaths: map[string]string{
			"ams":     "/v1/users:byUUID/{{identifier}}",
			"web-api": "/api/v2/admin/users:byID/{{identifier}}?export=flat",
		},
		ServiceTypesRetrievalFields: map[string]string{
			"ams":     "token",
			"web-api": "api_key",
		},
		SyslogEnabled:              true,
		ClientCertHostVerification: true,
		ServerReadTimeout:          15,
		ServerHeaderReadTimeout:    15,
		ServerWriteTimeout:         15,
		ServerIdleTimeout:          120,
	}

	//tests the case of a malformed json
	cfg3 := &Config{}
	err3 := cfg3.ConfigSetUp("./configuration-test-files/test-conf-invalid.json")

	// tests the case of an undeclared field in the json file
	cfg4 := &Config{}
	err4 := cfg4.ConfigSetUp("./configuration-test-files/test-conf-missing-field.json")

	// tests the case of an empty field in the json file
	cfg5 := &Config{}
	err5 := cfg5.ConfigSetUp("./configuration-test-files/test-conf-empty-field.json")

	suite.Equal(expCfg2, cfg2)

	suite.Equal("open /wrong/path: no such file or directory", err1.Error())
	suite.Nil(err2)
	suite.Equal("Something went wrong while marshaling the json data. Error: unexpected end of JSON input", err3.Error())
	suite.Equal("config object contains empty fields. empty value for field: service_port", err4.Error())
	suite.Equal("config object contains empty fields. empty value for field: mongo_host", err5.Error())

}

func (suite *ConfigTestSuite) TestClientAuthPolicy() {

	// trust unknown cas
	cfg1 := &Config{TrustUnknownCAs: true}

	// don't trust unknown cas
	cfg2 := &Config{TrustUnknownCAs: false}

	suite.Equal(tls.RequestClientCert, cfg1.ClientAuthPolicy())
	suite.Equal(tls.VerifyClientCertIfGiven, cfg2.ClientAuthPolicy())
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))

}
