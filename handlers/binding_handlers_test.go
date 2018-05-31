package handlers

import (
	"bytes"
	"github.com/ARGOeu/argo-api-authn/stores"
	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"net/http"
	"testing"

	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/gorilla/mux"
	"net/http/httptest"
)

type BindingHandlersSuite struct {
	suite.Suite
}

// TestBindingCreate tests the normal case of a binding creation
func (suite *BindingHandlersSuite) TestBindingCreate() {

	postJSON := `{
	"name": "new_binding",
	"service_uuid": "uuid1",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key": "uni_key"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	createdBind := bindings.Binding{}
	_ = json.Unmarshal([]byte(w.Body.String()), &createdBind)

	suite.Equal("uuid1", createdBind.ServiceUUID)
	suite.Equal("host1", createdBind.Host)
	suite.Equal("new_binding", createdBind.Name)
	suite.Equal("test_dn", createdBind.DN)
	suite.Equal("", createdBind.OIDCToken)
	suite.Equal("uni_key", createdBind.UniqueKey)

}

// TestBindingCreateMissingFieldName tests the case where the binding doesn't contain the  name field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldName() {

	postJSON := `{
	"service_uuid": "uuid1",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: Name",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateInvalidJSON tests the case where the request body is not a vlaid json
func (suite *BindingHandlersSuite) TestBindingCreateInvalidJSON() {

	postJSON := `{
	"service_uuid": "uuid1",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key": "uni_key"
`

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldServiceUUID tests the case where the binding doesn't contain the service_uuid field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldServiceUUID() {

	postJSON := `{
    "name": "b1",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: ServiceUUID",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldHost tests the case where the binding doesn't contain the host field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldHost() {

	postJSON := `{
    "name": "b1",
	"service_uuid": "uuid1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: Host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldDNAndOIDC tests the case where the binding doesn't contain both dn and oidc fields
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldDNAndOIDC() {

	postJSON := `{
    "name": "b1",
	"service_uuid": "uuid1",
    "host": "host1",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "Both DN and OIDC Token fields are empty",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldUniqueKey tests the case where the binding doesn't contain the service_uuid field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldUniqueKey() {

	postJSON := `{
    "name": "b1",
    "service_uuid": "uuid1",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": ""
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: UniqueKey",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateUnknownService tests the case where the service uuid is not known
func (suite *BindingHandlersSuite) TestBindingCreateUnknownService() {

	postJSON := `{
    "name": "b1",
    "service_uuid": "unknown",
    "host": "host1",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key":"key1"
}`

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingCreateUnknownHost() {

	postJSON := `{
    "name": "b1",
    "service_uuid": "uuid1",
    "host": "unknown",
    "dn": "test_dn",
    "oidc_token": "",
    "unique_key":"key1"
}`

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateDNAlreadyExists tests the case where the given dn is already used by another binding
func (suite *BindingHandlersSuite) TestBindingCreateDNAlreadyExists() {

	postJSON := `{
    "name": "b1",
    "service_uuid": "uuid1",
    "host": "host1",
    "dn": "test_dn_1",
    "oidc_token": "",
    "unique_key":"key1"
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object with dn: test_dn_1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAll tests the normal case
func (suite *BindingHandlersSuite) TestBindingListAll() {

	expRespJSON := `{
 "bindings": [
  {
   "name": "b1",
   "service_uuid": "uuid1",
   "host": "host1",
   "dn": "test_dn_1",
   "unique_key": "unique_key_1",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b2",
   "service_uuid": "uuid1",
   "host": "host1",
   "dn": "test_dn_2",
   "unique_key": "unique_key_2",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b3",
   "service_uuid": "uuid1",
   "host": "host2",
   "dn": "test_dn_3",
   "unique_key": "unique_key_3",
   "created_on": "2018-05-05T15:04:05Z"
  }
 ]
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllEmptyList tests the normal case
func (suite *BindingHandlersSuite) TestBindingListAllEmptyList() {

	expRespJSON := `{
 "bindings": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.Bindings = []stores.QBinding{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAll tests the normal case
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHost() {

	expRespJSON := `{
 "bindings": [
  {
   "name": "b1",
   "service_uuid": "uuid1",
   "host": "host1",
   "dn": "test_dn_1",
   "unique_key": "unique_key_1",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b2",
   "service_uuid": "uuid1",
   "host": "host1",
   "dn": "test_dn_2",
   "unique_key": "unique_key_2",
   "created_on": "2018-05-05T15:04:05Z"
  }
 ]
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllEmpty tests the empty case
func (suite *BindingHandlersSuite) TestBindingListAllEmpty() {

	expRespJSON := `{
 "bindings": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.Bindings = []stores.QBinding{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// estBindingListAllByServiceTypeAndHostEmpty tests the empty case
func (suite *BindingHandlersSuite) estBindingListAllByServiceTypeAndHostEmpty() {

	expRespJSON := `{
 "bindings": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host1/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.Bindings = []stores.QBinding{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllByServiceTypeAndHostUnknownServiceType tests the case where the service type is unknown
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHostUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host1/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllByServiceTypeAndHostUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHostUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/unknown_host/bindings", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDN tests the normal case
func (suite *BindingHandlersSuite) TestBindingListOneByDN() {

	expRespJSON := `{
 "name": "b1",
 "service_uuid": "uuid1",
 "host": "host1",
 "dn": "test_dn_1",
 "unique_key": "unique_key_1",
 "created_on": "2018-05-05T15:04:05Z"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListOneByDN, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownServiceType tests the case where the service type is unknown
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host1/bindings/test_dn_1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/unknown_host/bindings/test_dn_1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownDN tests the case where the dn doesn't match any binding under the host and service type
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownDN() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/bindings/unknown_dn", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListOneByDN, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdate tests the normal case of a updating a binding - updates the name
func (suite *BindingHandlersSuite) TestBindingUpdate() {

	postJSON := `{
	"name": "updated_name"
}`

	expRespJSON := `{
 "name": "updated_name",
 "service_uuid": "uuid1",
 "host": "host1",
 "dn": "test_dn_1",
 "unique_key": "unique_key_1",
 "created_on": "2018-05-05T15:04:05Z"
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateServiceUUIDEmpty tests case of updating a binding's service_uuid into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateServiceUUIDEmpty() {

	postJSON := `{
	"service_uuid": ""
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: ServiceUUID",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateHostEmpty tests case of updating a binding's host into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateHostEmpty() {

	postJSON := `{
	"host": ""
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: Host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUniqueKeyEmpty tests case of updating a binding's unique key into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateUniqueKeyEmpty() {

	postJSON := `{
	"unique_key": ""
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object contains an empty value for field: UniqueKey",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateDNEmpty tests case of updating a binding's dn into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateDNEmpty() {

	postJSON := `{
	"dn": ""
}`

	expRespJSON := `{
 "error": {
  "message": "Both DN and OIDC Token fields are empty",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownHost tests case of updating a binding's host into an unknown host
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownHost() {

	postJSON := `{
	"host": "unknown"
}`

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownServiceUUID tests case of updating a binding's service type uuid into an unknown service type uuid
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownServiceUUID() {

	postJSON := `{
	"service_uuid": "unknown"
}`

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateInvalidJSON tests case of updating a binding using an invalid json
func (suite *BindingHandlersSuite) TestBindingUpdateInvalidJSON() {

	postJSON := `{
	"service_uuid": "uuid2"
` // missing closing bracket

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateDNAlreadyExists tests case of updating a binding's dn into an already existing one
func (suite *BindingHandlersSuite) TestBindingUpdateDNAlreadyExists() {

	postJSON := `{
	"dn": "test_dn_2"
}`

	expRespJSON := `{
 "error": {
  "message": "bindings.Binding object with dn: test_dn_2 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/test_dn_1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownDNInPATH tests the case where the dn doesn't match any binding under the host and service type
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownDNInPATH() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host1/bindings/unknown_dn", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownHostInPATH tests the case where the host provided in the path doesn't exist
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownHostInPATH() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/unknown_host/bindings/test_dn_1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownServiceTypeInPATH tests the case where the service type provided in the path doesn't exist
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownServiceTypeInPATH() {

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/unknown/hosts/host1/bindings/test_dn_1", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

func TestBindingHandlersSuite(t *testing.T) {
	suite.Run(t, new(BindingHandlersSuite))
}
