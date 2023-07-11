package authmethods

import (
	"context"
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

	ctx := context.Background()

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	apk1 := ApiKeyAuthMethod{}
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key"}
	apk1.BasicAuthMethod = ba1
	// normal case
	apk1.AccessKey = "access_key"
	err1 := apk1.Validate(ctx, mockstore)

	// empty access_key
	apk1 = ApiKeyAuthMethod{}
	ba1 = BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key"}
	apk1.BasicAuthMethod = ba1
	err2 := apk1.Validate(ctx, mockstore)

	suite.Nil(err1)
	suite.Equal("auth method object contains empty fields. empty value for field: access_key", err2.Error())
}

func (suite *ApiKeyAuthMethodTestSuite) TestApiKeyAuthFinder() {

	ctx := context.Background()

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	var expectedQams []stores.QAuthMethod

	// normal case
	amb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, UUID: "am_uuid_1", CreatedOn: "", Type: "api-key"}
	am1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1
	expectedQams = append(expectedQams, am1)

	qAms, err1 := ApiKeyAuthFinder(ctx, "uuid1", "host1", mockstore)

	// nothing found
	qAms2, err2 := ApiKeyAuthFinder(ctx, "unknown_uuid", "host", mockstore)

	suite.Equal(expectedQams, qAms)
	suite.Equal(0, len(qAms2))

	suite.Nil(err1)
	suite.Nil(err2)
}

func (suite *ApiKeyAuthMethodTestSuite) TestUpdate() {

	apk1 := &ApiKeyAuthMethod{}
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key"}
	apk1.BasicAuthMethod = ba1

	// normal case - update some fields
	apkUpd1 := &ApiKeyAuthMethod{}
	baUpd1 := BasicAuthMethod{ServiceUUID: "some_uuid1", Host: "some_host", Port: 9090, Type: "api-key"}
	apkUpd1.BasicAuthMethod = baUpd1
	r1 := ConvertAuthMethodToReadCloser(apkUpd1)
	a1, err1 := apk1.Update(r1)
	ca1 := a1.(*ApiKeyAuthMethod)
	apkUpd1.UpdatedOn = ca1.UpdatedOn

	// update fields that aren't supposed to be updated
	apkUpd2 := &ApiKeyAuthMethod{}
	baUpd2 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "some_api-key", UUID: "some_uuid", CreatedOn: "some_time"}
	apkUpd2.BasicAuthMethod = baUpd2
	r2 := ConvertAuthMethodToReadCloser(apkUpd2)
	a2, err2 := apk1.Update(r2)
	ca2 := a2.(*ApiKeyAuthMethod)
	apk1.UpdatedOn = ca2.UpdatedOn

	suite.Equal(apkUpd1, a1)
	suite.Equal(apk1, a2)

	suite.Nil(err1)
	suite.Nil(err2)

}

func TestApiKeyAuthMethodSuite(t *testing.T) {
	suite.Run(t, new(ApiKeyAuthMethodTestSuite))
}
