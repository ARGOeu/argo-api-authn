package stores

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type StoreTestSuite struct {
	suite.Suite
	Mockstore Mockstore
}

// SetUpTestSuite assigns the mock store to be used in the querying tests
// It should be used on each test case so CRUD operations don't need to be reverted
func (suite *StoreTestSuite) SetUpStoreTestSuite() {

	mockstore := &Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()
	suite.Mockstore = *mockstore
}

// TestSetUp tests if the mockstore setup has been completed successfully
func (suite *StoreTestSuite) TestSetUp() {

	suite.SetUpStoreTestSuite()

	mockstore := &Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	var qServices []QServiceType
	var qBindings []QBinding

	// Populate qServices
	service1 := QServiceType{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}
	service2 := QServiceType{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", UUID: "uuid2", RetrievalField: "user_token", CreatedOn: "2018-05-05T18:04:05Z"}
	serviceSame1 := QServiceType{Name: "same_name"}
	serviceSame2 := QServiceType{Name: "same_name"}
	qServices = append(qServices, service1, service2, serviceSame1, serviceSame2)

	// Populate Bindings
	binding1 := QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := QBinding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding3 := QBinding{Name: "b3", ServiceUUID: "uuid1", Host: "host2", UUID: "b_uuid3", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	qBindings = append(qBindings, binding1, binding2, binding3)

	// Populate AuthMethods
	authMethods := []map[string]interface{}{{"service_uuid": "uuid1", "host": "host1", "port": 9000.0, "path": "test_path_1", "access_key": "key1", "type": "api-key"},
		{"host": "host2", "port": 9000.0, "path": "test_path_1", "type": "api-key", "service_uuid": "uuid1"},
		{"access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host3", "port": 9000.0},
		{"path": "test_path_1", "access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host4"}}

	suite.Equal(mockstore.Session, true)
	suite.Equal(mockstore.Database, "test_db")
	suite.Equal(mockstore.Server, "localhost")
	suite.Equal(mockstore.ServiceTypes, qServices)
	suite.Equal(mockstore.Bindings, qBindings)
	suite.Equal(mockstore.AuthMethods, authMethods)
}

func (suite *StoreTestSuite) TestClose() {

	suite.SetUpStoreTestSuite()

	suite.Mockstore.Close()
	suite.Equal(false, suite.Mockstore.Session)
}

func (suite *StoreTestSuite) TestQueryServiceTypes() {

	suite.SetUpStoreTestSuite()

	// normal case outcome - 1 service
	expQServices1 := []QServiceType{{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}}
	qServices1, err1 := suite.Mockstore.QueryServiceTypes("s1")
	expQServices2 := []QServiceType{{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", UUID: "uuid2", RetrievalField: "user_token", CreatedOn: "2018-05-05T18:04:05Z"}}
	qServices2, err2 := suite.Mockstore.QueryServiceTypes("s2")

	// normal case outcome - all services
	expQServicesAll := []QServiceType{
		{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"},
		{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", UUID: "uuid2", RetrievalField: "user_token", CreatedOn: "2018-05-05T18:04:05Z"},
		{Name: "same_name"},
		{Name: "same_name"},
	}
	qServicesAll, errAll := suite.Mockstore.QueryServiceTypes("")

	// was not found
	var expQService3 []QServiceType
	qServices3, err3 := suite.Mockstore.QueryServiceTypes("wrong_name")

	// tests the normal case - 1 service type
	suite.Equal(expQServices1, qServices1)
	suite.Nil(err1)
	suite.Equal(expQServices2, qServices2)
	suite.Nil(err2)

	// tests the normal case - all service types
	suite.Equal(expQServicesAll, qServicesAll)
	suite.Nil(errAll)

	// tests the not found case
	suite.Equal(expQService3, qServices3)
	suite.Nil(err3)
}

func (suite *StoreTestSuite) TestQueryServiceTypesByUUID() {

	suite.SetUpStoreTestSuite()

	// normal case outcome
	expQServices1 := []QServiceType{{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}}
	qServices1, err1 := suite.Mockstore.QueryServiceTypesByUUID("uuid1")

	// was not found
	var expQServices2 []QServiceType
	qServices2, err2 := suite.Mockstore.QueryServiceTypesByUUID("wrong_uuid")

	suite.Equal(expQServices1, qServices1)
	suite.Equal(expQServices2, qServices2)

	suite.Nil(err1)
	suite.Nil(err2)

}

func (suite *StoreTestSuite) TestQueryAuthMethods() {

	suite.SetUpStoreTestSuite()

	// normal case outcome
	expAuthMethod1 := []map[string]interface{}{{"type": "api-key", "service_uuid": "uuid1", "host": "host1", "path": "test_path_1", "port": 9000.0, "access_key": "key1"}}
	authMethod1, err1 := suite.Mockstore.QueryAuthMethods("uuid1", "host1", "api-key")

	// was not found
	authMethod2, err2 := suite.Mockstore.QueryAuthMethods("wrong_service", "wrong_host", "wrong_type")

	// normal case - all
	expAuthMethods := []map[string]interface{}{{"service_uuid": "uuid1", "host": "host1", "port": 9000.0, "path": "test_path_1", "access_key": "key1", "type": "api-key"},
		{"host": "host2", "port": 9000.0, "path": "test_path_1", "type": "api-key", "service_uuid": "uuid1"},
		{"access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host3", "port": 9000.0},
		{"path": "test_path_1", "access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host4"}}
	authMethods, err3 := suite.Mockstore.QueryAuthMethods("", "", "")

	// tests the normal case
	suite.Equal(expAuthMethod1, authMethod1)
	suite.Equal(0, len(authMethod2))
	suite.Equal(expAuthMethods, authMethods)

	suite.Nil(err1)
	suite.Nil(err2)
	suite.Nil(err3)
}

func (suite *StoreTestSuite) TestQueryBindingsByDN() {

	suite.SetUpStoreTestSuite()

	// normal case
	expBinding1 := []QBinding{{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}}
	qBinding1, err1 := suite.Mockstore.QueryBindingsByDN("test_dn_1", "uuid1", "host1")

	// not found case
	var expBinding2 []QBinding
	qBinding2, err2 := suite.Mockstore.QueryBindingsByDN("wrong_dn", "wrong_uuid", "wrong_host")

	// tests the normal case
	suite.Equal(expBinding1, qBinding1)
	suite.Nil(err1)

	//tests the not found case
	suite.Equal(expBinding2, qBinding2)
	suite.Nil(err2)
}

func (suite *StoreTestSuite) TestQueryBindingsByUUID() {

	suite.SetUpStoreTestSuite()

	// normal case
	expBinding1 := []QBinding{{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}}
	qBinding1, err1 := suite.Mockstore.QueryBindingsByUUID("b_uuid1")

	// not found case
	var expBinding2 []QBinding
	qBinding2, err2 := suite.Mockstore.QueryBindingsByUUID("wrong_uuid")

	// tests the normal case
	suite.Equal(expBinding1, qBinding1)
	suite.Nil(err1)

	//tests the not found case
	suite.Equal(expBinding2, qBinding2)
	suite.Nil(err2)
}

func (suite *StoreTestSuite) TestQueryBindings() {

	suite.SetUpStoreTestSuite()

	// normal case - with parameters
	expBindings1 := []QBinding{
		{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
	}
	qBindings1, err1 := suite.Mockstore.QueryBindings("uuid1", "host1")

	// normal case - without parameters
	expBindings2 := []QBinding{
		{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b3", ServiceUUID: "uuid1", Host: "host2", UUID: "b_uuid3", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
	}
	qBindings2, err2 := suite.Mockstore.QueryBindings("", "")

	// ot result case - with parameters
	var expBindings3 []QBinding
	qBindings3, err3 := suite.Mockstore.QueryBindings("wrong_service", "wrong_host")

	// tests the normal case - with parameters
	suite.Equal(expBindings1, qBindings1)
	suite.Nil(err1)

	// tests the normal case - without parameters
	suite.Equal(expBindings2, qBindings2)
	suite.Nil(err2)

	// tests the no result case - with parameters
	suite.Equal(expBindings3, qBindings3)
	suite.Nil(err3)
}

func (suite *StoreTestSuite) TestInsertServiceType() {

	suite.SetUpStoreTestSuite()

	_, err1 := suite.Mockstore.InsertServiceType("sIns", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "api-key", "uuid_ins", "token", "2018-05-05T18:04:05Z")

	expQServices1 := []QServiceType{{Name: "sIns", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid_ins", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}}
	qServices1, err1 := suite.Mockstore.QueryServiceTypes("sIns")

	suite.Equal(expQServices1[0], qServices1[0])
	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestInsertAuthMethod() {

	suite.SetUpStoreTestSuite()

	am := map[string]interface{}{"type": "api-key", "service_uuid": "s_temp", "host": "h_temp", "port": 9000.0, "path": "test_path_1", "access_key": "key1"}
	err := suite.Mockstore.InsertAuthMethod(am)
	amq, _ := suite.Mockstore.QueryAuthMethods("s_temp", "h_temp", "api-key")

	suite.Equal(am, amq[0])
	suite.Nil(err)
}

func (suite *StoreTestSuite) TestInsertBinding() {

	suite.SetUpStoreTestSuite()

	var expBinding1 QBinding
	_, err1 := suite.Mockstore.InsertBinding("bIns", "uuid1", "host1", "b_uuid", "test_dn_ins", "", "unique_key_ins")
	// check if the new binding can be found
	expBindings, _ := suite.Mockstore.QueryBindingsByDN("test_dn_ins", "uuid1", "host1")
	expBinding1 = expBindings[0]

	suite.Equal("bIns", expBinding1.Name)
	suite.Equal("uuid1", expBinding1.ServiceUUID)
	suite.Equal("host1", expBinding1.Host)
	suite.Equal("b_uuid", expBinding1.UUID)
	suite.Equal("test_dn_ins", expBinding1.DN)
	suite.Equal("", expBinding1.OIDCToken)
	suite.Equal("unique_key_ins", expBinding1.UniqueKey)
	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestUpdateBinding() {

	suite.SetUpStoreTestSuite()

	original := QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	updated := QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_upd", OIDCToken: "", UniqueKey: "unique_key_upd", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	_, err1 := suite.Mockstore.UpdateBinding(original, updated)

	expBindings, _ := suite.Mockstore.QueryBindingsByDN("test_dn_upd", "uuid1", "host1")
	expBinding1 := expBindings[0]

	suite.Equal(expBinding1, updated)
	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestUpdateServiceType() {

	suite.SetUpStoreTestSuite()

	original := QServiceType{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}

	updated := QServiceType{Name: "s_updated", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}


	_, err1 := suite.Mockstore.UpdateServiceType(original, updated)

	expSVTs, _ := suite.Mockstore.QueryServiceTypesByUUID("uuid1")
	expSVT1 := expSVTs[0]

	suite.Equal(expSVT1, updated)
	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestDeleteBinding() {

	suite.SetUpStoreTestSuite()

	qBinding := QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	err1 := suite.Mockstore.DeleteBinding(qBinding)

	// check the slice containing the bindings to see if the qBinding was removed
	expBindings := []QBinding{
		{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b3", ServiceUUID: "uuid1", Host: "host2", UUID: "b_uuid3", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
	}
	qBindings, _ := suite.Mockstore.QueryBindings("", "")

	suite.Equal(expBindings, qBindings)

	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestDeleteAuthMethod() {

	suite.SetUpStoreTestSuite()

	amD := map[string]interface{}{"service_uuid": "uuid1", "host": "host1", "port": 9000.0, "path": "test_path_1", "access_key": "key1", "type": "api-key"}

	err1 := suite.Mockstore.DeleteAuthMethod(amD)

	// check the slice containing the auth methods to see if the auth method was removed
	expAuthMs := []map[string]interface{}{{"host": "host2", "port": 9000.0, "path": "test_path_1", "type": "api-key", "service_uuid": "uuid1"},
		{"access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host3", "port": 9000.0},
		{"path": "test_path_1", "access_key": "key1", "type": "api-key", "service_uuid": "uuid2", "host": "host4"}}

	suite.Equal(expAuthMs, suite.Mockstore.AuthMethods)

	suite.Nil(err1)
}


func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}
