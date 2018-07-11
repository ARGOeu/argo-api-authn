package authmethods

import (
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type AuthMethodsTestSuite struct {
	suite.Suite
}

func (suite *AuthMethodsTestSuite) TestAuthMethodConvertToQueryModel() {

	// normal case, convert an api key auth method to its respective query model
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	apk1 := &ApiKeyAuthMethod{ba1, "access_key"}
	apk1.SetDefaults("ams")

	qba1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	qapk1 := &stores.QApiKeyAuthMethod{qba1, "access_key"}
	// manually add the fields that the SetDefaults() method provides
	qapk1.RetrievalField = apk1.RetrievalField
	qapk1.Path = apk1.Path

	qam, err := AuthMethodConvertToQueryModel(apk1, "api-key")

	suite.Equal(qapk1, qam)

	suite.Nil(err)

}

func (suite *AuthMethodsTestSuite) TestQueryModelConvertToAuthMethod() {

	// normal case, convert an query model to an api key auth method
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	apk1 := &ApiKeyAuthMethod{ba1, "access_key"}
	apk1.SetDefaults("ams")

	qba1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	qapk1 := &stores.QApiKeyAuthMethod{qba1, "access_key"}
	// manually add the fields that the SetDefaults() method provides
	qapk1.RetrievalField = apk1.RetrievalField
	qapk1.Path = apk1.Path

	qam, err := QueryModelConvertToAuthMethod(qapk1, "api-key")

	suite.Equal(qam, apk1)

	suite.Nil(err)
}

func (suite *AuthMethodsTestSuite) TestAuthMethodFinder() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "test_path_1", UUID: "am_uuid_1", Type: "api-key"}
	expectedApk1 := &ApiKeyAuthMethod{ba1, "access_key"}

	apk1, err1 := AuthMethodFinder("uuid1", "host1", "api-key", mockstore)

	// not found case
	_, err2 := AuthMethodFinder("uuid_unknown", "unknown", "api-key", mockstore)

	// more than 1 found
	// append a temporary query auth method
	amb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "test_path_1", UUID: "am_uuid_1", CreatedOn: "", Type: "api-key"}
	am1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1
	mockstore.AuthMethods = append(mockstore.AuthMethods, am1)
	_, err3 := AuthMethodFinder("uuid1", "host1", "api-key", mockstore)
	suite.Equal(expectedApk1, apk1)

	suite.Nil(err1)
	suite.Equal("Auth method was not found", err2.Error())
	suite.Equal("Internal Error: More than 1 auth methods found for the given service type and host", err3.Error())

}

func (suite *AuthMethodsTestSuite) TestAuthMethodAlreadyExists() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	err1 := AuthMethodAlreadyExists("uuid1", "host1", "api-key", mockstore)

	suite.Equal("Auth method object with host: host1 already exists", err1.Error())

}

func (suite *AuthMethodsTestSuite) TestAuthMethodCreate() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000, Type: "api-key"}
	apk1 := &ApiKeyAuthMethod{ba1, "access_key"}
	apk1.SetDefaults("ams")

	qamb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000, Type: "api-key"}
	qam1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	qam1.QBasicAuthMethod = qamb1
	// manually add the fields that the SetDefaults() method provides
	qam1.RetrievalField = apk1.RetrievalField
	qam1.Path = apk1.Path

	err1 := AuthMethodCreate(apk1, mockstore, "api-key")
	ll, _ := mockstore.QueryApiKeyAuthMethods("uuid1", "host2")

	suite.Equal(apk1.ServiceUUID, ll[0].ServiceUUID)
	suite.Equal(apk1.Host, ll[0].Host)
	suite.Equal(apk1.Path, ll[0].Path)
	suite.Equal(apk1.RetrievalField, ll[0].RetrievalField)
	suite.Equal(apk1.Port, ll[0].Port)
	suite.NotEqual("", ll[0].UUID)      // check that uuid has been set
	suite.NotEqual("", ll[0].CreatedOn) // check that created time has been set

	suite.Nil(err1)

}

func TestAuthMethodTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMethodsTestSuite))
}
