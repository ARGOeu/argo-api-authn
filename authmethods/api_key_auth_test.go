package authmethods

import (
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type ApiKeyAuthMethodTestSuite struct {
	suite.Suite
}

func (suite *ApiKeyAuthMethodTestSuite) TestNewApiKeyAuthMethod() {

	apk1 := NewApiKeyAuthMethod()

	suite.Equal(&ApiKeyAuthMethod{}, apk1)
}

func (suite *ApiKeyAuthMethodTestSuite) TestValidate() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	apk1 := ApiKeyAuthMethod{}
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	apk1.BasicAuthMethod = ba1
	// normal case
	apk1.AccessKey = "access_key"
	apk1.SetDefaults("ams")
	err1 := apk1.Validate(mockstore)

	// empty access_key
	apk1 = ApiKeyAuthMethod{}
	ba1 = BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	apk1.BasicAuthMethod = ba1
	err2 := apk1.Validate(mockstore)

	// path doesn't contain {{identifier}}
	apk1.AccessKey = "some_key"
	apk1.Path = "/some/path?key={{access_key}}"
	err3 := apk1.Validate(mockstore)

	// path doesn't contain {{access_key}}
	apk1.Path = "/some/path/{{identifier}}/"
	err4 := apk1.Validate(mockstore)

	suite.Nil(err1)
	suite.Equal("auth method object contains empty fields. empty value for field: access_key", err2.Error())
	suite.Equal("Field: path contains invalid data. Missing {{identifier}} interpolation", err3.Error())
	suite.Equal("Field: path contains invalid data. Missing {{access_key}} interpolation", err4.Error())
}

func (suite *ApiKeyAuthMethodTestSuite) TestFill() {

	// normal case
	apk1 := ApiKeyAuthMethod{}

	err1 := apk1.SetDefaults("ams")

	// not found paths
	err2 := apk1.SetDefaults("unknown")

	// not found in retrieval fields (we need to bypass the paths check so we add it there temporarily"
	ApiKeyAuthMethodsPaths["unknown_rf_but_not_type"] = ""
	err3 := apk1.SetDefaults("unknown_rf_but_not_type")

	suite.Equal("/v1/users:byUUID/{{identifier}}?key={{access_key}}", apk1.Path)
	suite.Equal("token", apk1.RetrievalField)

	suite.Nil(err1)
	suite.Equal("Internal Error: Type is supported but not found", err2.Error())
	suite.Equal("Internal Error: Type is supported but not found", err3.Error())
}

func (suite *ApiKeyAuthMethodTestSuite) TestApiKeyAuthFinder() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	var expectedQams []stores.QAuthMethod

	// normal case
	amb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "test_path_1", UUID: "am_uuid_1", CreatedOn: "", Type: "api-key"}
	am1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1
	expectedQams = append(expectedQams, am1)

	qAms, err1 := ApiKeyAuthFinder("uuid1", "host1", mockstore)

	// nothing found
	qAms2, err2 := ApiKeyAuthFinder("unknown_uuid", "host", mockstore)

	suite.Equal(expectedQams, qAms)
	suite.Equal(0, len(qAms2))

	suite.Nil(err1)
	suite.Nil(err2)
}

func TestApiKeyAuthMethod_Fill(t *testing.T) {
	suite.Run(t, new(ApiKeyAuthMethodTestSuite))
}
