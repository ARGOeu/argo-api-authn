package servicetypes

import (
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type ServiceTestSuite struct {
	suite.Suite
}

func (suite *ServiceTestSuite) TestCreateServiceType() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	// test the normal case with type ams
	s1 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1",  "", "ams"}
	_, err := CreateServiceType(s1, mockstore, *cfg)
	res1, _ := mockstore.QueryServiceTypes("sCr")

	// test the normal case with type web-api
	sWb := ServiceType{"sCr_wb", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "token",  "web-api"}
	_, errWb := CreateServiceType(sWb, mockstore, *cfg)
	res2, _ := mockstore.QueryServiceTypes("sCr_wb")

	// test the normal case with type custom
	sCustom := ServiceType{"sCr_custom", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "token", "custom"}
	_, errCustom := CreateServiceType(sCustom, mockstore, *cfg)
	res3, _ := mockstore.QueryServiceTypes("sCr_custom")

	// test the case where the name already exists
	s2 := ServiceType{"s1", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "some_uuid", "", "ams"}
	_, err2 := CreateServiceType(s2, mockstore, *cfg)

	// test the case of unsupported auth type
	s3 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"unsup_type", "oidc"}, "api-key", "some_uuid", "", "ams"}
	_, err3 := CreateServiceType(s3, mockstore, *cfg)

	// test the case of empty auth type list
	s4 := ServiceType{"sCr", []string{"host1", "host2"}, []string{}, "api-key", "some_uuid", "", "ams"}
	_, err4 := CreateServiceType(s4, mockstore, *cfg)

	// test the case of unsupported auth method
	s5 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "unsup_method", "some_uuid", "", "ams"}
	_, err5 := CreateServiceType(s5, mockstore, *cfg)

	// test the case of empty name
	s6 := ServiceType{"", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "", "ams"}
	_, err6 := CreateServiceType(s6, mockstore, *cfg)

	// test the case of empty auth method
	s8 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "", "uuid1", "", "ams"}
	_, err8 := CreateServiceType(s8, mockstore, *cfg)

	// test the case of empty hosts
	s9 := ServiceType{"sCr", []string{}, []string{"x509", "oidc"}, "api-key", "uuid1", "", "ams"}
	_, err9 := CreateServiceType(s9, mockstore, *cfg)

	// test the case of empty type
	s10 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "", ""}
	_, err10 := CreateServiceType(s10, mockstore, *cfg)

	// test the case of unsupported type type
	s11 := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "", "unsup_type"}
	_, err11 := CreateServiceType(s11, mockstore, *cfg)

	suite.Equal(s1.Name, res1[0].Name)
	suite.Equal(s1.Hosts, res1[0].Hosts)
	suite.Equal(s1.AuthTypes, res1[0].AuthTypes)
	suite.Equal(s1.AuthMethod, res1[0].AuthMethod)

	suite.Equal(sWb.Name, res2[0].Name)
	suite.Equal(sWb.Hosts, res2[0].Hosts)
	suite.Equal(sWb.AuthTypes, res2[0].AuthTypes)
	suite.Equal(sWb.AuthMethod, res2[0].AuthMethod)

	suite.Equal(sCustom.Name, res3[0].Name)
	suite.Equal(sCustom.Hosts, res3[0].Hosts)
	suite.Equal(sCustom.AuthTypes, res3[0].AuthTypes)
	suite.Equal(sCustom.AuthMethod, res3[0].AuthMethod)

	suite.Nil(err)
	suite.Nil(errWb)
	suite.Nil(errCustom)
	suite.Equal("service-type object with name: s1 already exists", err2.Error())
	suite.Equal("auth_types: unsup_type is not yet supported.Supported:[x509 oidc]", err3.Error())
	suite.Equal("auth_types: empty is not yet supported.Supported:[x509 oidc]", err4.Error())
	suite.Equal("auth_method: unsup_method is not yet supported.Supported:[api-key x-api-token]", err5.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: name", err6.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: auth_method", err8.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: hosts", err9.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: type", err10.Error())
	suite.Equal("type: unsup_type is not yet supported.Supported:[ams web-api custom]", err11.Error())

}

func (suite *ServiceTestSuite) TestFindServiceTypeByName() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	expS1 := ServiceType{"s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "api-key", "uuid1", "2018-05-05T18:04:05Z", "ams"}
	ser1, err1 := FindServiceTypeByName("s1", mockstore)

	// not found case
	var expS2 ServiceType
	ser2, err2 := FindServiceTypeByName("not_found", mockstore)

	// same name
	var expS3 ServiceType
	ser3, err3 := FindServiceTypeByName("same_name", mockstore)

	suite.Equal(expS1, ser1)
	suite.Equal(expS2, ser2)
	suite.Equal(expS3, ser3)

	suite.Nil(err1)
	suite.Equal("Service-type was not found", err2.Error())
	suite.Equal("Database Error: Multiple service-types with the same name: same_name", err3.Error())
}

func (suite *ServiceTestSuite) TestFindServiceTypeByUUID() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case
	expS1 := ServiceType{"s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "api-key", "uuid1", "2018-05-05T18:04:05Z", "ams"}
	ser1, err1 := FindServiceTypeByUUID("uuid1", mockstore)

	// not found case
	var expS2 ServiceType
	ser2, err2 := FindServiceTypeByUUID("wrong_uuid", mockstore)

	// same name
	var expS3 ServiceType
	// insert two service s with the same name
	mockstore.InsertServiceType("s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "api-key", "same_uuid", "2018-05-05T18:04:05Z", "ams")
	mockstore.InsertServiceType("s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "api-key", "same_uuid", "2018-05-05T18:04:05Z", "ams")
	ser3, err3 := FindServiceTypeByUUID("same_uuid", mockstore)

	suite.Equal(expS1, ser1)
	suite.Equal(expS2, ser2)
	suite.Equal(expS3, ser3)

	suite.Nil(err1)
	suite.Equal("Service-type was not found", err2.Error())
	suite.Equal("Database Error: Multiple service-types with the same uuid: same_uuid", err3.Error())
}

func (suite *ServiceTestSuite) TestFindAllServiceTypes() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// normal case outcome - all services
	expQServicesAll := []ServiceType{
		{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", CreatedOn: "2018-05-05T18:04:05Z", Type: "ams"},
		{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", UUID: "uuid2", CreatedOn: "2018-05-05T18:04:05Z", Type: "ams"},
		{Name: "same_name"},
		{Name: "same_name"},
	}
	expServList := ServiceTypesList{expQServicesAll}
	serAll1, err1 := FindAllServiceTypes(mockstore)

	// normal case outcome - empty list
	var empServ = ServiceTypesList{ServiceTypes: []ServiceType{}}
	mockstore.ServiceTypes = []stores.QServiceType{}
	serAll2, err2 := FindAllServiceTypes(mockstore)

	suite.Equal(expServList, serAll1)
	suite.Equal(empServ, serAll2)

	suite.Nil(err1)
	suite.Nil(err2)
}

func (suite *ServiceTestSuite) TestServiceTypeHasHost() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	ser := ServiceType{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, UUID: "uuid1", AuthMethod: "api-key", CreatedOn: "2018-05-05T18:04:05Z"}

	suite.Equal(true, ser.HasHost("host1"))
	suite.Equal(false, ser.HasHost("host_unknown"))

}

func (suite *ServiceTestSuite) TestUpdateService() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	// original service type
	qOriginal := stores.QServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "", "ams"}
	original := ServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "uuid1", "", "ams"}
	mockstore.ServiceTypes = append(mockstore.ServiceTypes, qOriginal)

	// test the normal case
	s1 := TempServiceType{"sCr_upd", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "token"}
	_, err := UpdateServiceType(original, s1, mockstore, *cfg)
	res1, _ := mockstore.QueryServiceTypes("sCr_upd")

	// test the case where the name already exists
	s2 := TempServiceType{"s1", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "token"}
	_, err2 := UpdateServiceType(original, s2, mockstore, *cfg)

	// test the case of unsupported auth type
	s3 := TempServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "unsup_type"}, "api-key", "token"}
	_, err3 := UpdateServiceType(original, s3, mockstore, *cfg)

	// test the case of empty auth type list
	s4 := TempServiceType{"sCr", []string{"host1", "host2"}, []string{}, "api-key", "token"}
	_, err4 := UpdateServiceType(original, s4, mockstore, *cfg)

	// test the case of unsupported auth method
	s5 := TempServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "unsup_method", "token"}
	_, err5 := UpdateServiceType(original, s5, mockstore, *cfg)

	// test the case of empty name
	s6 := TempServiceType{"", []string{"host1", "host2"}, []string{"x509", "oidc"}, "api-key", "token"}
	_, err6 := UpdateServiceType(original, s6, mockstore, *cfg)

	// test the case of empty auth method
	s8 := TempServiceType{"sCr", []string{"host1", "host2"}, []string{"x509", "oidc"}, "", "token"}
	_, err8 := UpdateServiceType(original, s8, mockstore, *cfg)

	// test the case of empty hosts
	s9 := TempServiceType{"sCr", []string{}, []string{"x509", "oidc"}, "api-key", "token"}
	_, err9 := UpdateServiceType(original, s9, mockstore, *cfg)

	suite.Equal(s1.Name, res1[0].Name)
	suite.Equal(s1.Hosts, res1[0].Hosts)
	suite.Equal(s1.AuthTypes, res1[0].AuthTypes)
	suite.Equal(s1.AuthMethod, res1[0].AuthMethod)

	suite.Nil(err)
	suite.Equal("service-type object with name: s1 already exists", err2.Error())
	suite.Equal("auth_types: unsup_type is not yet supported.Supported:[x509 oidc]", err3.Error())
	suite.Equal("auth_types: empty is not yet supported.Supported:[x509 oidc]", err4.Error())
	suite.Equal("auth_method: unsup_method is not yet supported.Supported:[api-key x-api-token]", err5.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: name", err6.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: auth_method", err8.Error())
	suite.Equal("service-type object contains empty fields. empty value for field: hosts", err9.Error())

}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}
