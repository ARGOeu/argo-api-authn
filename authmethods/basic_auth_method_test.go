package authmethods

import (
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type BasicAuthMethodTestSuite struct {
	suite.Suite
}

func (suite *BasicAuthMethodTestSuite) TestValidate() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	err1 := ba1.Validate(mockstore)

	// unknown service uuid
	ba2 := BasicAuthMethod{ServiceUUID: "unknown", Host: "host1", Port: 9000, Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	err2 := ba2.Validate(mockstore)

	// unknown host
	ba3 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "unknown", Port: 9000, Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	err3 := ba3.Validate(mockstore)

	// invalid path
	ba5 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: ":::fff/", RetrievalField: "token", Type: "api-key"}
	err5 := ba5.Validate(mockstore)

	// missing service_uuid
	ba6 := BasicAuthMethod{Host: "host1", Port: 9000, Path: ":::fff/", RetrievalField: "token", Type: "api-key"}
	err6 := ba6.Validate(mockstore)

	// missing host
	ba7 := BasicAuthMethod{ServiceUUID: "uuid1", Port: 9000, Path: ":::fff/", RetrievalField: "token", Type: "api-key"}
	err7 := ba7.Validate(mockstore)

	// missing port
	ba8 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Path: "/v1/sone/{{obj}}?key={{obj2}}", RetrievalField: "token", Type: "api-key"}
	err8 := ba8.Validate(mockstore)

	// missing path
	ba9 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, RetrievalField: "token", Type: "api-key"}
	err9 := ba9.Validate(mockstore)

	// missing retrieval field
	ba10 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Path: "/v1/some/{{obj}}?key={{obj2}}", Type: "api-key"}
	err10 := ba10.Validate(mockstore)

	suite.Nil(err1)
	suite.Equal("Service-type was not found", err2.Error())
	suite.Equal("Host was not found", err3.Error())
	suite.Equal("The url to access resources in invalid. URL: https://host1:9000:::fff/", err5.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: service_uuid", err6.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: host", err7.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: port", err8.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: path", err9.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: retrieval_field", err10.Error())

}

func TestBasicAuthMethodTestSuite(t *testing.T) {
	suite.Run(t, new(BasicAuthMethodTestSuite))
}
