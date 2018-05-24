package handlers

import (
	"bytes"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"
)

type AuthMethodHandlersTestSuite struct {
	suite.Suite
}

// TestAuthMethodListOne tests the normal case and returns the information of the auth method under the given service type and host
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOne() {

	expRespJSON := `{
 "access_key": "key1",
 "host": "host1",
 "path": "test_path_1",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

//TestAuthMethodListOneUndeclaredAccessKey tests the case where the auth method doesn't contain the required access key
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOneUndeclaredAccessKey() {

	expRespJSON := `{
 "error": {
  "message": "Database Error: Access Key was not found in the ApiKeyAuth object",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host2/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

//TestAuthMethodListOneUndeclaredPath tests the case where the auth method doesn't contain the required path
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOneUndeclaredPath() {

	expRespJSON := `{
 "error": {
  "message": "Database Error: Path was not found in the ApiKeyAuth object",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s2/hosts/host3/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

//TestAuthMethodListOneUndeclaredPort tests the case where the auth method doesn't contain the required port
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOneUndeclaredPort() {

	expRespJSON := `{
 "error": {
  "message": "Database Error: Port was not found in the ApiKeyAuth object",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s2/hosts/host4/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestAuthMethodListOneUnknownServiceType tests the case where the given service type doesn't exist
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOneUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host4/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestAuthMethodListOneUnknownHost tests the case where the given host is associated with the given service type
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListOneUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host_unknown/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service}/hosts/{host}/authM", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestAuthMethodListAll tests the normal case and returns all auth methods in the service type
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodListAll() {

	expRespJSON := `{
 "auth_methods": [
  {
   "access_key": "key1",
   "host": "host1",
   "path": "test_path_1",
   "port": 9000,
   "service_uuid": "uuid1",
   "type": "api-key"
  },
  {
   "host": "host2",
   "path": "test_path_1",
   "port": 9000,
   "service_uuid": "uuid1",
   "type": "api-key"
  },
  {
   "access_key": "key1",
   "host": "host3",
   "port": 9000,
   "service_uuid": "uuid2",
   "type": "api-key"
  },
  {
   "access_key": "key1",
   "host": "host4",
   "path": "test_path_1",
   "service_uuid": "uuid2",
   "type": "api-key"
  }
 ]
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/authM", nil)
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreate tests the normal case of creating an auth method
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreate() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`

	expRespJSON := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestAuthMethodInvalidJSON tests the case where the request body contains a malformed json
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateInvalidJSON() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service": "s1",
 "type": "api-key"
` // missing closing bracket

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodEmptyReqBody tests the case where the request body contains an empty body
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateEmptyReqBody() {

	postBody := `{}`

	expRespJSON := `{
 "error": {
  "message": "Field: all fields contains invalid data. Empty request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingTypeField tests the case where the request body doesn't contain the type field
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingTypeField() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service": "s1"
}`
	expRespJSON := `{
 "error": {
  "message": "Type was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnsupportedAuthMethod tests the case where the type field contains an unsupported auth method by the authentication service
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateUnsupportedAuthMethod() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "unsupported-type"
}`
	expRespJSON := `{
 "error": {
  "message": "Field: type contains invalid data. unsupported-type is not yet supported by the serviceType",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingServiceField tests the case where the request body doesn't contain the service field
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingServiceField() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "ServiceType UUID was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingHostField tests the case where the request body doesn't contain the service host
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingHostField() {

	postBody := `{
 "access_key": "key1",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "type": "api-key",
 "service_uuid": "uuid1"
}`
	expRespJSON := `{
 "error": {
  "message": "Host was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingPortField tests the case where the request body doesn't contain the port field
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingPortField() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "type": "api-key",
 "service_uuid": "uuid1"
}`
	expRespJSON := `{
 "error": {
  "message": "Port was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingPathField tests the case where the request body doesn't contain the path field
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingPathField() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "Path was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateMissingAccessKeyField tests the case where the request body doesn't contain the access_key field
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateMissingAccessKeyField() {

	postBody := `{
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "access_key was not found in the request body",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnknownService tests the case where the service hasn't yet been registered
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateUnknownService() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "port": 9000,
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "type": "api-key",
 "service_uuid": "unknown_service"
}`
	expRespJSON := `{
 "error": {
  "message": "ServiceType was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnknownHost tests the case where the host is not associated with the given service
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateUnknownHost() {

	postBody := `{
 "access_key": "key1",
 "host": "unknown_host",
 "port": 9000,
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "type": "api-key",
 "service_uuid": "uuid1"
}`
	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnknownAuthMethod tests the case where the specific service doesn't support the given auth method
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateUnknownAuthMethod() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "port": 9000,
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "type": "unknown_authM",
 "service_uuid": "uuid1"
}`
	expRespJSON := `{
 "error": {
  "message": "Field: type contains invalid data. unknown_authM is not yet supported by the serviceType",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateInvalidPathContentAccessKey tests the case where the path field doesn't contain the string interpolation of {{access_key}}
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateInvalidPathContentAccessKey() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1/{{identifier}}?key=",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "Field: path contains invalid data. Doesn't contain {{access_key}}",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateInvalidPathContentIdentifier tests the case where the path field doesn't contain the string interpolation of {{identifier}}
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateInvalidPathContentIdentifier() {

	postBody := `{
 "access_key": "key1",
 "host": "host3",
 "path": "test_path_1?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "Field: path contains invalid data. Doesn't contain {{identifier}}",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateAlreadyExists tests the case where the service under the given hosts, has an already declared auth method
func (suite *AuthMethodHandlersTestSuite) TestAuthMethodCreateAlreadyExists() {

	postBody := `{
 "access_key": "key1",
 "host": "host1",
 "path": "test_path_1/{{identifier}}?key={{access_key}}",
 "port": 9000,
 "service_uuid": "uuid1",
 "type": "api-key"
}`
	expRespJSON := `{
 "error": {
  "message": "auth_methods.AuthMethod object with serviceType: uuid1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/authM", bytes.NewBuffer([]byte(postBody)))
	if err != nil {
		log.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authM", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

func TestAuthMethodHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMethodHandlersTestSuite))
}
