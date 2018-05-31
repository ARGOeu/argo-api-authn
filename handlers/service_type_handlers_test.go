package handlers

import (
	"bytes"
	"github.com/stretchr/testify/suite"
	"net/http"
	"testing"

	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http/httptest"
)

type ServiceTypeHandlersSuite struct {
	suite.Suite
}

// TestServiceTypeCreate tests the normal case of a service type creation
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreate() {

	postJSON := `{
	"name": "service1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	createdSer := servicetypes.ServiceType{}
	_ = json.Unmarshal([]byte(w.Body.String()), &createdSer)

	suite.Equal("service1", createdSer.Name)
	suite.Equal([]string{"127.0.0.1"}, createdSer.Hosts)
	suite.Equal([]string{"x509", "oidc"}, createdSer.AuthTypes)
	suite.Equal("api-key", createdSer.AuthMethod)
	suite.Equal("token", createdSer.RetrievalField)

}

// TestServiceTypeCreateInvalidName tests the case where the service type's name already exists
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidName() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	expRespJSON := `{
 "error": {
  "message": "servicetypes.ServiceType object with name: s1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidAuthTypes tests the case where the service type's auth types are not yet supported
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidAuthTypes() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["unsup_type", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	expRespJSON := `{
 "error": {
  "message": "Authentication Type: unsup_type is not yet supported",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidAuthMethod tests the case where the service type's auth method are not yet supported
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidAuthMethod() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "unsup_method",
	"retrieval_field": "token"
}`

	expRespJSON := `{
 "error": {
  "message": "Authentication Method: unsup_method is not yet supported",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateEmptyAuthTypes tests the case where the service type's auth types are empty
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateEmptyAuthTypes() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": [],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	expRespJSON := `{
 "error": {
  "message": "Authentication Type: empty is not yet supported",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidJSON tests the case of the request containing an invalid json body
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidJSON() {

	postJSON := `{
	"name": "service1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
}`

	expResJSON := `{
 "error": {
  "message": "Poorly formatted JSON. invalid character '}' looking for beginning of object key string",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expResJSON, w.Body.String())
}

// TestServiceTypeCreateMissingField tests the case of the request containing an incomplete json body
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateMissingField() {

	postJSON := `{
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	expResJSON := `{
 "error": {
  "message": "servicetypes.ServiceType object contains an empty value for field: Name",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expResJSON, w.Body.String())
}

// TestServiceTypeListOne tests the normal case
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOne() {

	expResJSON := `{
 "name": "s1",
 "hosts": [
  "host1",
  "host2",
  "host3"
 ],
 "auth_types": [
  "x509",
  "oidc"
 ],
 "auth_method": "api-key",
 "uuid": "uuid1",
 "retrieval_field": "token",
 "created_on": "2018-05-05T18:04:05Z"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListOneNameCollision tests the case where two or more service types exist with the same name
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOneNameCollision() {

	expResJSON := `{
 "error": {
  "message": "Database Error: Multiple service-types with the same name: same_name",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/same_name", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListOneNotFound tests the case where two or more service types exist with the same name
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOneNotFound() {

	expResJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/not_found", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListAll tests the normal functionality of listing all services types
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListAll() {

	expResJSON := `{
 "service_types": [
  {
   "name": "s1",
   "hosts": [
    "host1",
    "host2",
    "host3"
   ],
   "auth_types": [
    "x509",
    "oidc"
   ],
   "auth_method": "api-key",
   "uuid": "uuid1",
   "retrieval_field": "token",
   "created_on": "2018-05-05T18:04:05Z"
  },
  {
   "name": "s2",
   "hosts": [
    "host3",
    "host4"
   ],
   "auth_types": [
    "x509"
   ],
   "auth_method": "api-key",
   "uuid": "uuid2",
   "retrieval_field": "user_token",
   "created_on": "2018-05-05T18:04:05Z"
  },
  {
   "name": "same_name",
   "hosts": null,
   "auth_types": null,
   "auth_method": "",
   "uuid": "",
   "retrieval_field": "",
   "created_on": ""
  },
  {
   "name": "same_name",
   "hosts": null,
   "auth_types": null,
   "auth_method": "",
   "uuid": "",
   "retrieval_field": "",
   "created_on": ""
  }
 ]
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types", nil)

	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestsServiceListAllEmptyList tests the case of an empty service types list
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListAllEmptyList() {

	expResJSON := `{
 "service_types": []
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.ServiceTypes = []stores.QServiceType{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

func TestHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTypeHandlersSuite))
}
