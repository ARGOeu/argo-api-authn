package authmethods

import (
	"context"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type HeadersAuthMethodTestSuite struct {
	suite.Suite
}

func (suite *HeadersAuthMethodTestSuite) TestNewHeadersAuthMethod() {

	apk1 := NewHeadersAuthMethod()

	suite.Equal(&HeadersAuthMethod{}, apk1)
}

func (suite *HeadersAuthMethodTestSuite) TestValidate() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// normal case
	amb2 := BasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	ham := HeadersAuthMethod{BasicAuthMethod: amb2, Headers: map[string]string{"x-api-key": "headers=key-1", "Accept": "application/json"}}
	err1 := ham.Validate(ctx, mockstore)

	// empty headers
	ham2 := HeadersAuthMethod{BasicAuthMethod: amb2}
	err2 := ham2.Validate(ctx, mockstore)

	suite.Nil(err1)
	suite.Equal("auth method object contains empty fields. empty value for field: headers", err2.Error())
}

func (suite *HeadersAuthMethodTestSuite) TestHeadersAuthFinder() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	var expectedQams []stores.QAuthMethod

	ctx := context.Background()

	// normal case
	amb2 := stores.QBasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	ham := stores.QHeadersAuthMethod{QBasicAuthMethod: amb2, Headers: map[string]string{"x-api-key": "key-1", "Accept": "application/json"}}
	expectedQams = append(expectedQams, &ham)

	qAms, err1 := HeadersAuthFinder(ctx, "uuid2", "host3", mockstore)

	// nothing found
	qAms2, err2 := HeadersAuthFinder(ctx, "unknown_uuid", "host", mockstore)

	suite.Equal(expectedQams, qAms)
	suite.Equal(0, len(qAms2))

	suite.Nil(err1)
	suite.Nil(err2)
}

func (suite *HeadersAuthMethodTestSuite) TestUpdate() {

	amb2 := BasicAuthMethod{ServiceUUID: "uuid2", Host: "host4", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	ham := HeadersAuthMethod{BasicAuthMethod: amb2, Headers: map[string]string{"x-api-key": "key-2", "Accept": "application/json"}}

	// normal case - update some fields
	amb2 = BasicAuthMethod{ServiceUUID: "uuid2", Host: "host4", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	hamUpd1 := HeadersAuthMethod{BasicAuthMethod: amb2, Headers: map[string]string{"x-api-key": "key-2", "Accept": "application/json"}}
	r1 := ConvertAuthMethodToReadCloser(&hamUpd1)
	a1, err1 := hamUpd1.Update(r1)
	ca1 := a1.(*HeadersAuthMethod)
	ham.UpdatedOn = ca1.UpdatedOn

	// update fields that aren't supposed to be updated
	apkUpd2 := &HeadersAuthMethod{}
	baUpd2 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "some_api-key", UUID: "some_uuid", CreatedOn: "some_time"}
	apkUpd2.BasicAuthMethod = baUpd2
	r2 := ConvertAuthMethodToReadCloser(apkUpd2)
	a2, err2 := apkUpd2.Update(r2)

	suite.Equal(&ham, a1)
	suite.NotEqual(ham, a2)

	suite.Nil(err1)
	suite.Nil(err2)

}

func TestHeadersAuthMethodSuite(t *testing.T) {
	suite.Run(t, new(HeadersAuthMethodTestSuite))
}
