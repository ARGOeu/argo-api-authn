package authmethods

import (
	"bytes"
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"io"
	"io/ioutil"
	"testing"
)

type AuthMethodsTestSuite struct {
	suite.Suite
}

func ConvertAuthMethodToReadCloser(am AuthMethod) io.ReadCloser {

	bb, _ := json.Marshal(am)

	reader := bytes.NewReader(bb)

	return ioutil.NopCloser(reader)

}

func (suite *AuthMethodsTestSuite) TestAuthMethodConvertToQueryModel() {

	// normal case, convert an api key auth method to its respective query model
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	apk1 := &ApiKeyAuthMethod{ba1, "access_key"}

	qba1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	qapk1 := &stores.QApiKeyAuthMethod{qba1, "access_key"}

	qam, err := AuthMethodConvertToQueryModel(apk1, "api-key")

	suite.Equal(qapk1, qam)

	suite.Nil(err)

}

func (suite *AuthMethodsTestSuite) TestQueryModelConvertToAuthMethod() {

	// normal case, convert an query model to an api key auth method
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	apk1 := &ApiKeyAuthMethod{ba1, "access_key"}

	qba1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000}
	qapk1 := &stores.QApiKeyAuthMethod{qba1, "access_key"}

	qam, err := QueryModelConvertToAuthMethod(qapk1, "api-key")

	suite.Equal(qam, apk1)

	suite.Nil(err)
}

func (suite *AuthMethodsTestSuite) TestAuthMethodFinder() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	ba1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, UUID: "am_uuid_1", Type: "api-key"}
	expectedApk1 := &ApiKeyAuthMethod{ba1, "access_key"}

	apk1, err1 := AuthMethodFinder("uuid1", "host1", "api-key", mockstore)

	// not found case
	_, err2 := AuthMethodFinder("uuid_unknown", "unknown", "api-key", mockstore)

	// more than 1 found
	// append a temporary query auth method
	amb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, UUID: "am_uuid_1", CreatedOn: "", Type: "api-key"}
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

	qamb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host2", Port: 9000, Type: "api-key"}
	qam1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	qam1.QBasicAuthMethod = qamb1

	err1 := AuthMethodCreate(apk1, mockstore, "api-key")
	ll, _ := mockstore.QueryApiKeyAuthMethods("uuid1", "host2")

	suite.Equal(apk1.ServiceUUID, ll[0].ServiceUUID)
	suite.Equal(apk1.Host, ll[0].Host)
	suite.Equal(apk1.Port, ll[0].Port)
	suite.NotEqual("", ll[0].UUID)      // check that uuid has been set
	suite.NotEqual("", ll[0].CreatedOn) // check that created time has been set

	suite.Nil(err1)

}

func (suite *AuthMethodsTestSuite) TestAuthMethodFIndAll() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	var expAmList AuthMethodsList

	// test the normal case
	amb1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	apiKeyAm := &ApiKeyAuthMethod{AccessKey: "access_key"}
	apiKeyAm.BasicAuthMethod = amb1

	amb2 := BasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	headersAm := &HeadersAuthMethod{Headers: map[string]string{"x-api-key": "key-1", "Accept": "application/json"}}
	headersAm.BasicAuthMethod = amb2

	expAmList.AuthMethods = append(expAmList.AuthMethods, apiKeyAm, headersAm)

	aMList, err1 := AuthMethodFindAll(mockstore)
	suite.Equal(2, len(aMList.AuthMethods))

	for _, _am := range aMList.AuthMethods {
		_, ok := _am.(*ApiKeyAuthMethod)
		if ok {
			suite.Equal(apiKeyAm, _am)
		} else {
			suite.Equal(headersAm, _am)
		}
	}

	suite.Nil(err1)

	// empty list
	mockstore.AuthMethods = []stores.QAuthMethod{}
	aMList2, err2 := AuthMethodFindAll(mockstore)
	suite.Equal(0, len(aMList2.AuthMethods))
	suite.Nil(err2)
}

func (suite *AuthMethodsTestSuite) TestAuthMethodDelete() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// test the normal case
	amb1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am1 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	am1.BasicAuthMethod = amb1

	err1 := AuthMethodDelete(am1, mockstore)

	suite.Equal(1, len(mockstore.AuthMethods))

	suite.Nil(err1)
}

func (suite *AuthMethodsTestSuite) TestAuthMethodUpdate() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	amb1 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am1 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	am1.BasicAuthMethod = amb1

	// normal case - update some fields (with updated service uuid and host)
	ambU1 := BasicAuthMethod{ServiceUUID: "uuid2", Host: "host4", Port: 9090, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU1 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU1.BasicAuthMethod = ambU1
	r1 := ConvertAuthMethodToReadCloser(amU1)
	a1, err1 := AuthMethodUpdate(am1, r1, mockstore)
	ca1 := a1.(*ApiKeyAuthMethod)
	amU1.UpdatedOn = ca1.UpdatedOn

	// normal case - update fields that can't be updated
	ambU2 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "some_api-key", UUID: "some_am_uuid_1", CreatedOn: "some_time"}
	amU2 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU2.BasicAuthMethod = ambU2
	r2 := ConvertAuthMethodToReadCloser(amU2)
	a2, err2 := AuthMethodUpdate(am1, r2, mockstore)
	amU2.UpdatedOn = ca1.UpdatedOn
	am1.UpdatedOn = ca1.UpdatedOn

	// unknown service uuid
	ambU3 := BasicAuthMethod{ServiceUUID: "unknown", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU3 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU3.BasicAuthMethod = ambU3
	r3 := ConvertAuthMethodToReadCloser(amU3)
	a3, err3 := AuthMethodUpdate(am1, r3, mockstore)
	amU3.UpdatedOn = ca1.UpdatedOn

	// unknown host
	ambU4 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "unknown", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU4 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU4.BasicAuthMethod = ambU4
	r4 := ConvertAuthMethodToReadCloser(amU4)
	a4, err4 := AuthMethodUpdate(am1, r4, mockstore)
	amU4.UpdatedOn = ca1.UpdatedOn

	// empty service uuid
	ambU6 := BasicAuthMethod{ServiceUUID: "", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU6 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU6.BasicAuthMethod = ambU6
	r6 := ConvertAuthMethodToReadCloser(amU6)
	a6, err6 := AuthMethodUpdate(am1, r6, mockstore)
	amU6.UpdatedOn = ca1.UpdatedOn

	// empty host
	ambU7 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU7 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU7.BasicAuthMethod = ambU7
	r7 := ConvertAuthMethodToReadCloser(amU7)
	a7, err7 := AuthMethodUpdate(am1, r7, mockstore)
	amU7.UpdatedOn = ca1.UpdatedOn

	// empty port
	ambU8 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 0, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU8 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU8.BasicAuthMethod = ambU8
	r8 := ConvertAuthMethodToReadCloser(amU8)
	a8, err8 := AuthMethodUpdate(am1, r8, mockstore)
	amU8.UpdatedOn = ca1.UpdatedOn

	// empty access key
	ambU10 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 10000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU10 := &ApiKeyAuthMethod{AccessKey: ""}
	amU10.BasicAuthMethod = ambU10
	r10 := ConvertAuthMethodToReadCloser(amU10)
	a10, err10 := AuthMethodUpdate(am1, r10, mockstore)
	amU10.UpdatedOn = ca1.UpdatedOn

	// auth method for host and service already exists
	amb2 := BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am2 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	am2.BasicAuthMethod = amb2
	ambU11 := BasicAuthMethod{ServiceUUID: "uuid2", Host: "host4", Port: 11000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	amU11 := &ApiKeyAuthMethod{AccessKey: "access_key"}
	amU11.BasicAuthMethod = ambU11
	r11 := ConvertAuthMethodToReadCloser(amU11)
	a11, err11 := AuthMethodUpdate(am2, r11, mockstore)
	amU11.UpdatedOn = ca1.UpdatedOn

	suite.Equal(a1, amU1)
	suite.Equal(a2, am1)
	suite.Equal(a3, amU3)
	suite.Equal(a4, amU4)
	suite.Equal(a6, amU6)
	suite.Equal(a7, amU7)
	suite.Equal(a8, amU8)
	suite.Equal(a10, amU10)
	suite.Equal(a11, amU11)

	suite.Nil(err1)
	suite.Nil(err2)
	suite.Equal("Service-type was not found", err3.Error())
	suite.Equal("Host was not found", err4.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: service_uuid", err6.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: host", err7.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: port", err8.Error())
	suite.Equal("auth method object contains empty fields. empty value for field: access_key", err10.Error())
	suite.Equal("Auth method object with host: host4 already exists", err11.Error())
}

func TestAuthMethodTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMethodsTestSuite))
}
