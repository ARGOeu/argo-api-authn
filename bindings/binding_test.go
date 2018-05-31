package bindings

import (
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type BindingTestSuite struct {
	suite.Suite
}

func (suite *BindingTestSuite) TestCreateBinding() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// test the normal case
	b1 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err1 := CreateBinding(b1, mockstore)
	res1, _ := mockstore.QueryBindingsByDN("dn_ins", "uuid1", "host1")

	// tests the case of missing field name
	b2 := Binding{ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err2 := CreateBinding(b2, mockstore)

	// tests the case with missing field serviceUUID
	b3 := Binding{Name: "bins", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err3 := CreateBinding(b3, mockstore)

	// tests the case with missing field host
	b4 := Binding{Name: "bins", ServiceUUID: "uuid1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err4 := CreateBinding(b4, mockstore)

	// tests the case with missing field uniquekey
	b5 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: ""}
	_, err5 := CreateBinding(b5, mockstore)

	// tests the case with missing field dn and oidctoken
	b6 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", UniqueKey: "key"}
	_, err6 := CreateBinding(b6, mockstore)

	// tests the case with unknown service uuid
	b7 := Binding{Name: "bins", ServiceUUID: "unknown", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err7 := CreateBinding(b7, mockstore)

	// tests the case with unknown host
	b8 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "unknown", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err8 := CreateBinding(b8, mockstore)

	// tests the case where a binding with the given dn already exists
	b9 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "key"}
	_, err9 := CreateBinding(b9, mockstore)

	suite.Equal(b1.Name, res1[0].Name)
	suite.Equal(b1.ServiceUUID, res1[0].ServiceUUID)
	suite.Equal(b1.Host, res1[0].Host)
	suite.Equal(b1.OIDCToken, res1[0].OIDCToken)
	suite.Equal(b1.UniqueKey, res1[0].UniqueKey)

	suite.Nil(err1)
	suite.Equal("bindings.Binding object contains an empty value for field: Name", err2.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: ServiceUUID", err3.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: Host", err4.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: UniqueKey", err5.Error())
	suite.Equal("Both DN and OIDC Token fields are empty", err6.Error())
	suite.Equal("ServiceType was not found", err7.Error())
	suite.Equal("Host was not found", err8.Error())
	suite.Equal("bindings.Binding object with dn: test_dn_1 already exists", err9.Error())

}

func (suite *BindingTestSuite) TestFindBindingByDN() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// tests the normal case
	expBinding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1"}
	b1, err1 := FindBindingByDN("test_dn_1", "uuid1", "host1", mockstore)

	suite.Equal(expBinding1.Name, b1.Name)
	suite.Equal(expBinding1.ServiceUUID, b1.ServiceUUID)
	suite.Equal(expBinding1.Host, b1.Host)
	suite.Equal(expBinding1.DN, b1.DN)
	suite.Equal(expBinding1.UniqueKey, b1.UniqueKey)

	// tests the not found case
	_, err2 := FindBindingByDN("unknown", "unknown", "unknown", mockstore)

	// tests the case of more than 2 bindigs with the same dn exist under the same host and service
	// append one more binding , same to an existing
	mockstore.Bindings = append(mockstore.Bindings, stores.QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1"})
	_, err3 := FindBindingByDN("test_dn_1", "uuid1", "host1", mockstore)

	suite.Nil(err1)
	suite.Equal("Binding was not found", err2.Error())
	suite.Equal("Database Error: More than 1 bindings found under the service type: uuid1 and host: host1 using the same DN: test_dn_1", err3.Error())

}

func (suite *BindingTestSuite) TestFindAllBindings() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// tests the normal case
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding3 := Binding{Name: "b3", ServiceUUID: "uuid1", Host: "host2", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1, binding2, binding3)

	bl, err := FindAllBindings(mockstore)

	// test the empty list case
	mockstore.Bindings = []stores.QBinding{} // empty the mockstore
	b2, err2 := FindAllBindings(mockstore)

	suite.Equal(expectedBL, bl)
	suite.Equal(0, len(b2.Bindings))

	suite.Nil(err2)
	suite.Nil(err)
}

func (suite *BindingTestSuite) TestFindBindingsByServiceTypeAndHost() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// tests the normal case
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1, binding2)

	b1, err1 := FindBindingsByServiceTypeAndHost("uuid1", "host1", mockstore)

	// tests the empty list case
	b2, err2 := FindBindingsByServiceTypeAndHost("unknown_service", "unknown_host", mockstore)

	suite.Equal(expectedBL, b1)
	suite.Equal(0, len(b2.Bindings))

	suite.Nil(err1)
	suite.Nil(err2)

}

func (suite *BindingTestSuite) TestupdateBinding() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// insert a binding
	b1_ins := stores.QBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	mockstore.Bindings = append(mockstore.Bindings, b1_ins)

	b1 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}

	// test the normal case
	b1_upd := Binding{Name: "bins_tmp", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins_tmp", OIDCToken: "", UniqueKey: "key_tmp"}
	_, err1 := UpdateBinding(b1, b1_upd, mockstore)
	res1, _ := mockstore.QueryBindingsByDN("dn_ins_tmp", "uuid1", "host1")

	// tests the case of providing an empty name
	b2 := Binding{Name: "", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err2 := UpdateBinding(b1, b2, mockstore)

	// tests the case of providing an empty serviceUUID
	b3 := Binding{Name: "bins", ServiceUUID: "", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err3 := UpdateBinding(b1, b3, mockstore)

	// tests the case of providing an empty host
	b4 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err4 := UpdateBinding(b1, b4, mockstore)

	// tests the case of providing an empty unique key
	b5 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: ""}
	_, err5 := UpdateBinding(b1, b5, mockstore)

	// tests the case with missing field dn and oidctoken
	b6 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", UniqueKey: "key", DN: "", OIDCToken: ""}
	_, err6 := UpdateBinding(b1, b6, mockstore)

	// tests the case with unknown service uuid
	b7 := Binding{Name: "bins", ServiceUUID: "unknown", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err7 := UpdateBinding(b1, b7, mockstore)

	// tests the case with unknown host
	b8 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "unknown", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}
	_, err8 := UpdateBinding(b1, b8, mockstore)

	// tests the case where a binding with the given dn already exists
	b9 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "key"}
	_, err9 := UpdateBinding(b1, b9, mockstore)

	suite.Equal(b1_upd.Name, res1[0].Name)
	suite.Equal(b1_upd.ServiceUUID, res1[0].ServiceUUID)
	suite.Equal(b1_upd.Host, res1[0].Host)
	suite.Equal(b1_upd.OIDCToken, res1[0].OIDCToken)
	suite.Equal(b1_upd.UniqueKey, res1[0].UniqueKey)

	suite.Nil(err1)
	suite.Equal("bindings.Binding object contains an empty value for field: Name", err2.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: ServiceUUID", err3.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: Host", err4.Error())
	suite.Equal("bindings.Binding object contains an empty value for field: UniqueKey", err5.Error())
	suite.Equal("Both DN and OIDC Token fields are empty", err6.Error())
	suite.Equal("ServiceType was not found", err7.Error())
	suite.Equal("Host was not found", err8.Error())
	suite.Equal("bindings.Binding object with dn: test_dn_1 already exists", err9.Error())

}

func (suite *BindingTestSuite) TestDeleteBinding() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	b_del := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	err1 := DeleteBinding(b_del, mockstore)

	// tests the normal case
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1)

	bL1, _ := FindBindingsByServiceTypeAndHost("uuid1", "host1", mockstore)

	suite.Equal(expectedBL, bL1)

	suite.Nil(err1)

}

func TestBindingTestSuite(t *testing.T) {
	suite.Run(t, new(BindingTestSuite))
}
