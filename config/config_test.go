package config

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) TestConfigSetUp() {

	// tests the case of a wrong path to a config file
	cfg1 := &Config{}
	err1 := cfg1.ConfigSetUp("/wrong/path")

	// tests the case of a normal setup
	cfg2 := &Config{}
	err2 := cfg2.ConfigSetUp("./configuration-test-files/test-conf.json")
	expCfg2 := &Config{9000, "test_mongo_host", "test_mongo_db", "/path/to/cas", "/path/to/cert", "/path/to/key", "token", []string{"x509", "oidc"}, []string{"api-key", "x-api-token"}}

	//tests the case of a malformed json
	cfg3 := &Config{}
	err3 := cfg3.ConfigSetUp("./configuration-test-files/test-conf-invalid.json")

	// tests the case of an undeclared field in the json file
	cfg4 := &Config{}
	err4 := cfg4.ConfigSetUp("./configuration-test-files/test-conf-missing-field.json")
	expCfg4 := &Config{0, "test_mongo_host", "test_mongo_db", "/path/to/cas", "/path/to/cert", "/path/to/key", "token", []string{"x509", "oidc"}, []string{"api-key", "x-api-token"}}

	// tests the case of an empty field in the json file
	cfg5 := &Config{}
	err5 := cfg5.ConfigSetUp("./configuration-test-files/test-conf-empty-field.json")
	expCfg5 := &Config{9000, "", "test_mongo_db", "/path/to/cas", "/path/to/cert", "/path/to/key", "token", []string{"x509", "oidc"}, []string{"api-key", "x-api-token"}}

	suite.Equal(cfg2, expCfg2)
	suite.Equal(cfg3, &Config{})
	suite.Equal(cfg4, expCfg4)
	suite.Equal(cfg5, expCfg5)

	suite.Equal("open /wrong/path: no such file or directory", err1.Error())
	suite.Nil(err2)
	suite.Equal("Something went wrong while marshaling the json data. Error: unexpected end of JSON input", err3.Error())
	suite.Equal("config.Config object contains an empty value for field: ServicePort", err4.Error())
	suite.Equal("config.Config object contains an empty value for field: MongoHost", err5.Error())

}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))

}