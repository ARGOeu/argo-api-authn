package bindings

import (
	"context"
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

	ctx := context.Background()

	// test the normal case
	b1 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err1 := CreateBinding(ctx, b1, mockstore)
	res1, _ := mockstore.QueryBindingsByAuthID(ctx, "dn_ins", "uuid1", "host1", "x509")

	// tests the case of missing field name
	b2 := Binding{ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err2 := CreateBinding(ctx, b2, mockstore)

	// tests the case with missing field serviceUUID
	b3 := Binding{Name: "bins", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err3 := CreateBinding(ctx, b3, mockstore)

	// tests the case with missing field host
	b4 := Binding{Name: "bins", ServiceUUID: "uuid1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err4 := CreateBinding(ctx, b4, mockstore)

	// tests the case with missing field uniquekey
	b5 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins"}
	_, err5 := CreateBinding(ctx, b5, mockstore)

	// tests the case with missing field dn and oidctoken
	b6 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", UniqueKey: "key", AuthType: "x509"}
	_, err6 := CreateBinding(ctx, b6, mockstore)

	// tests the case with unknown service uuid
	b7 := Binding{Name: "bins", ServiceUUID: "unknown", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err7 := CreateBinding(ctx, b7, mockstore)

	// tests the case with unknown host
	b8 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "unknown", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err8 := CreateBinding(ctx, b8, mockstore)

	// tests the case where a binding with the given dn already exists
	b9 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_dn_1", UniqueKey: "key", AuthType: "x509"}
	_, err9 := CreateBinding(ctx, b9, mockstore)

	// tests the case where a binding's auth type is not supported by is service type
	b10 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_auth", UniqueKey: "key", AuthType: "unknown"}
	_, err10 := CreateBinding(ctx, b10, mockstore)

	// tests the case where a binding with the given name already exists
	b11 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_dn_1_1", UniqueKey: "key", AuthType: "x509"}
	_, err11 := CreateBinding(ctx, b11, mockstore)

	suite.Equal(b1.Name, res1[0].Name)
	suite.Equal(b1.ServiceUUID, res1[0].ServiceUUID)
	suite.Equal(b1.Host, res1[0].Host)
	suite.NotEqual("", res1[0].UUID)
	suite.Equal(b1.UniqueKey, res1[0].UniqueKey)

	suite.Nil(err1)
	suite.Equal("binding object contains empty fields. empty value for field: name", err2.Error())
	suite.Equal("binding object contains empty fields. empty value for field: service_uuid", err3.Error())
	suite.Equal("binding object contains empty fields. empty value for field: host", err4.Error())
	suite.Equal("binding object contains empty fields. empty value for field: unique_key", err5.Error())
	suite.Equal("binding object contains empty fields. empty value for field: auth_identifier", err6.Error())
	suite.Equal("Service-type was not found", err7.Error())
	suite.Equal("Host was not found", err8.Error())
	suite.Equal("binding object with auth_identifier: test_dn_1 already exists", err9.Error())
	suite.Equal("Auth type: unknown is not yet supported.Supported:[x509 oidc]", err10.Error())
	suite.Equal("binding object with name: b1 already exists", err11.Error())

}

func (suite *BindingTestSuite) TestFindBindingByDN() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// tests the normal case
	expBinding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509"}
	b1, err1 := FindBindingByAuthID(ctx, "test_dn_1", "uuid1", "host1", "x509", mockstore)

	suite.Equal(expBinding1.Name, b1.Name)
	suite.Equal(expBinding1.ServiceUUID, b1.ServiceUUID)
	suite.Equal(expBinding1.Host, b1.Host)
	suite.Equal(expBinding1.AuthIdentifier, b1.AuthIdentifier)
	suite.Equal(expBinding1.UniqueKey, b1.UniqueKey)
	suite.Equal(expBinding1.AuthType, b1.AuthType)

	// tests the not found case
	_, err2 := FindBindingByAuthID(ctx, "unknown", "unknown", "unknown", "x509", mockstore)

	// tests the case of more than 2 bindigs with the same dn exist under the same host and service
	// append one more binding , same to an existing
	mockstore.Bindings = append(mockstore.Bindings, stores.QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509"})
	_, err3 := FindBindingByAuthID(ctx, "test_dn_1", "uuid1", "host1", "x509", mockstore)

	suite.Nil(err1)
	suite.Equal("Binding was not found", err2.Error())
	suite.Equal("Database Error: More than 1 bindings found under the service type: uuid1 and host: host1 using the same AuthIdentifier: test_dn_1", err3.Error())

}

func (suite *BindingTestSuite) TestFindBindingByUUIDAndName() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// tests the normal case
	expBinding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509"}
	b1, err1 := FindBindingByUUIDAndName(ctx, "b_uuid1", "", mockstore)
	b1_name, err1_name := FindBindingByUUIDAndName(ctx, "", "b1", mockstore)

	suite.Equal(expBinding1.Name, b1.Name)
	suite.Equal(expBinding1.ServiceUUID, b1.ServiceUUID)
	suite.Equal(expBinding1.Host, b1.Host)
	suite.Equal(expBinding1.UUID, b1.UUID)
	suite.Equal(expBinding1.AuthIdentifier, b1.AuthIdentifier)
	suite.Equal(expBinding1.UniqueKey, b1.UniqueKey)
	suite.Equal(expBinding1.AuthType, b1.AuthType)

	suite.Equal(expBinding1.Name, b1_name.Name)
	suite.Equal(expBinding1.ServiceUUID, b1_name.ServiceUUID)
	suite.Equal(expBinding1.Host, b1_name.Host)
	suite.Equal(expBinding1.UUID, b1_name.UUID)
	suite.Equal(expBinding1.AuthIdentifier, b1_name.AuthIdentifier)
	suite.Equal(expBinding1.UniqueKey, b1_name.UniqueKey)
	suite.Equal(expBinding1.AuthType, b1_name.AuthType)

	// tests the not found case
	_, err2 := FindBindingByUUIDAndName(ctx, "unknown", "", mockstore)

	// tests the case of more than 2 bindigs with the same dn exist under the same host and service
	// append one more binding , same to an existing
	mockstore.Bindings = append(mockstore.Bindings, stores.QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1"})
	_, err3 := FindBindingByUUIDAndName(ctx, "b_uuid1", "", mockstore)

	suite.Nil(err1)
	suite.Nil(err1_name)
	suite.Equal("Binding was not found", err2.Error())
	suite.Equal("Database Error: More than 1 Bindings found with the same UUID: b_uuid1", err3.Error())

}

func (suite *BindingTestSuite) TestFindAllBindings() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// tests the normal case
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", AuthIdentifier: "test_dn_2", UniqueKey: "unique_key_2", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding3 := Binding{Name: "b3", ServiceUUID: "uuid1", Host: "host2", UUID: "b_uuid3", AuthIdentifier: "test_dn_3", UniqueKey: "unique_key_3", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding4 := Binding{Name: "b4", ServiceUUID: "uuid2", Host: "host3", UUID: "b_uuid4", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1, binding2, binding3, binding4)

	bl, err := FindAllBindings(ctx, mockstore)

	// test the empty list case
	mockstore.Bindings = []stores.QBinding{} // empty the mockstore
	b2, err2 := FindAllBindings(ctx, mockstore)

	suite.Equal(expectedBL, bl)
	suite.Equal(0, len(b2.Bindings))

	suite.Nil(err2)
	suite.Nil(err)
}

func (suite *BindingTestSuite) TestFindBindingsByServiceTypeAndHost() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// tests the normal case
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", AuthIdentifier: "test_dn_2", UniqueKey: "unique_key_2", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1, binding2)

	b1, err1 := FindBindingsByServiceTypeAndHost(ctx, "uuid1", "host1", mockstore)

	// tests the empty list case
	b2, err2 := FindBindingsByServiceTypeAndHost(ctx, "unknown_service", "unknown_host", mockstore)

	suite.Equal(expectedBL, b1)
	suite.Equal(0, len(b2.Bindings))

	suite.Nil(err1)
	suite.Nil(err2)

}

func (suite *BindingTestSuite) TestUpdateBinding() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	// insert a binding
	b1_ins := stores.QBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	mockstore.Bindings = append(mockstore.Bindings, b1_ins)

	b1 := Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}

	// test the normal case
	b1_upd := TempUpdateBinding{Name: "bins_tmp", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins_tmp", UniqueKey: "key_tmp", AuthType: "x509"}
	_, err1 := UpdateBinding(ctx, b1, b1_upd, mockstore)
	res1, _ := mockstore.QueryBindingsByAuthID(ctx, "dn_ins_tmp", "uuid1", "host1", "x509")

	// tests the case of providing an empty name
	b2 := TempUpdateBinding{Name: "", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err2 := UpdateBinding(ctx, b1, b2, mockstore)

	// tests the case of providing an empty serviceUUID
	b3 := TempUpdateBinding{Name: "bins", ServiceUUID: "", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err3 := UpdateBinding(ctx, b1, b3, mockstore)

	// tests the case of providing an empty host
	b4 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err4 := UpdateBinding(ctx, b1, b4, mockstore)

	// tests the case of providing an empty unique key
	b5 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: ""}
	_, err5 := UpdateBinding(ctx, b1, b5, mockstore)

	// tests the case with missing auth id field
	b6 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", UniqueKey: "key", AuthIdentifier: ""}
	_, err6 := UpdateBinding(ctx, b1, b6, mockstore)

	// tests the case with unknown service uuid
	b7 := TempUpdateBinding{Name: "bins", ServiceUUID: "unknown", Host: "host1", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err7 := UpdateBinding(ctx, b1, b7, mockstore)

	// tests the case with unknown host
	b8 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "unknown", AuthIdentifier: "dn_ins", UniqueKey: "key", AuthType: "x509"}
	_, err8 := UpdateBinding(ctx, b1, b8, mockstore)

	// tests the case where a binding with the given dn already exists
	b9 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_dn_1", UniqueKey: "key", AuthType: "x509"}
	_, err9 := UpdateBinding(ctx, b1, b9, mockstore)

	// tests the case with missing auth id field
	b10 := TempUpdateBinding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", UniqueKey: "key", AuthIdentifier: "test_dn_1", AuthType: ""}
	_, err10 := UpdateBinding(ctx, b1, b10, mockstore)

	// tests the case where a binding with the given dn already exists
	b11 := TempUpdateBinding{Name: "b4", ServiceUUID: "uuid1", Host: "host1", AuthIdentifier: "test_dn_4", UniqueKey: "key", AuthType: "x509"}
	_, err11 := UpdateBinding(ctx, b1, b11, mockstore)

	suite.Equal(b1_upd.Name, res1[0].Name)
	suite.Equal(b1_upd.ServiceUUID, res1[0].ServiceUUID)
	suite.Equal(b1_upd.Host, res1[0].Host)
	suite.Equal(b1_upd.UniqueKey, res1[0].UniqueKey)

	suite.Nil(err1)
	suite.Equal("binding object contains empty fields. empty value for field: name", err2.Error())
	suite.Equal("binding object contains empty fields. empty value for field: service_uuid", err3.Error())
	suite.Equal("binding object contains empty fields. empty value for field: host", err4.Error())
	suite.Equal("binding object contains empty fields. empty value for field: unique_key", err5.Error())
	suite.Equal("binding object contains empty fields. empty value for field: auth_identifier", err6.Error())
	suite.Equal("Service-type was not found", err7.Error())
	suite.Equal("Host was not found", err8.Error())
	suite.Equal("binding object with auth_identifier: test_dn_1 already exists", err9.Error())
	suite.Equal("binding object contains empty fields. empty value for field: auth_type", err10.Error())
	suite.Equal("binding object with name: b4 already exists", err11.Error())

}

func (suite *BindingTestSuite) TestDeleteBinding() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	ctx := context.Background()

	b_del := Binding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	err1 := DeleteBinding(ctx, b_del, mockstore)

	// tests the normal case - query the store to find if the deleted binding is indeed missing
	expectedBL := BindingList{}
	binding1 := Binding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", AuthIdentifier: "test_dn_2", UniqueKey: "unique_key_2", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	expectedBL.Bindings = append(expectedBL.Bindings, binding1)

	bL1, _ := FindBindingsByServiceTypeAndHost(ctx, "uuid1", "host1", mockstore)

	suite.Equal(expectedBL, bL1)

	suite.Nil(err1)

}

func TestBindingTestSuite(t *testing.T) {
	suite.Run(t, new(BindingTestSuite))
}
