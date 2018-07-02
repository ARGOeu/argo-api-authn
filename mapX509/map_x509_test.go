package mapX509

import (
	"github.com/ARGOeu/argo-api-authn/auth-methods"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	LOGGER "github.com/sirupsen/logrus"
	"testing"
)

type MapX509Suite struct {
	suite.Suite
}

// MockServiceTypeEndpoint mocks the behavior of a service type endpoint and returns a response containing the requested resource
func MockServiceTypeEndpoint(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("{\"token\": \"some-value\"}"))
}

// MockServiceTypeEndpoint500Error mocks the behavior when the http client produces a 500 error
func MockServiceTypeEndpoint500Error(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
	w.Write([]byte("Some internal error"))
}
func (suite *MapX509Suite) TestMapX509ToAuthItem() {

	// set up
	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	// append a service type to be used only in auth via cert tests
	qSt := stores.QServiceType{Name: "s_auth_cert", Hosts: []string{"h1_auth_cert"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "mock-api-key", UUID: "uuid_auth_cert", RetrievalField: "token", CreatedOn: "2018-05-05T18:04:05Z"}
	qSt2 := stores.QServiceType{Name: "s_auth_cert_incorrect", Hosts: []string{"h1_auth_cert"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "mock-api-key", UUID: "uuid_auth_cert_incorrect", RetrievalField: "incorrect_field", CreatedOn: "2018-05-05T18:04:05Z"}
	mockstore.ServiceTypes = append(mockstore.ServiceTypes, qSt, qSt2)
	// append a binding to be used only in auth via cert tests
	qB := stores.QBinding{Name: "b_auth_cert", ServiceUUID: "uuid_auth_cert", Host: "h1_auth_cert", DN: "O=COMPANY,L=CITY,ST=TN,C=TC", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	qB2 := stores.QBinding{Name: "b_auth_cert_incorrect", ServiceUUID: "uuid_auth_cert_incorrect", Host: "h1_auth_cert", DN: "O=COMPANY,L=CITY,ST=TN,C=TC", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	mockstore.Bindings = append(mockstore.Bindings, qB, qB2)

	// add a mock auth method handler
	auth_methods.AuthMethodHandlers["mock-api-key"] =
		func(data map[string]interface{}, store stores.Store, config *config.Config) (*http.Response, error) {

			var req2 *http.Request
			var err error

			// mock the request that will take place against the given service type
			if req2, err = http.NewRequest("GET", "http://localhost:8080/some_endpoint", nil); err != nil {
				LOGGER.Error(err.Error())
			}
			router := mux.NewRouter().StrictSlash(true)
			w := httptest.NewRecorder()
			router.HandleFunc("/some_endpoint", MockServiceTypeEndpoint)
			router.ServeHTTP(w, req2)
			return w.Result(), err
		}

	serviceType1 := servicetypes.ServiceType{"s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "mock-api-key", "uuid1", "token", "2018-05-05T18:04:05Z"}
	b1 := bindings.Binding{Name: "bins", ServiceUUID: "uuid1", Host: "host1", DN: "dn_ins", OIDCToken: "", UniqueKey: "key"}

	// tests the normal case
	expM1 := map[string]interface{}{"token": "some-value"}
	m1, err1 := DeprecatedMapX509ToAuthItem(serviceType1, b1, "host1", mockstore, cfg)

	// tests the case where a 500 error is produced
	// add a mock auth method handler for the 500 case
	serviceType2 := servicetypes.ServiceType{"s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "mock-api-key-500", "uuid1", "token", "2018-05-05T18:04:05Z"}
	auth_methods.AuthMethodHandlers["mock-api-key-500"] =
		func(data map[string]interface{}, store stores.Store, config *config.Config) (*http.Response, error) {

			var req2 *http.Request
			var err error

			// mock the request that will take place against the given service type
			if req2, err = http.NewRequest("GET", "http://localhost:8080/some_endpoint", nil); err != nil {
				LOGGER.Error(err.Error())
			}
			router := mux.NewRouter().StrictSlash(true)
			w := httptest.NewRecorder()
			router.HandleFunc("/some_endpoint", MockServiceTypeEndpoint500Error)
			router.ServeHTTP(w, req2)
			return w.Result(), err
		}
	_, err2 := DeprecatedMapX509ToAuthItem(serviceType2, b1, "host1", mockstore, cfg)

	// tests the case where the service type's retrieval field can't be found inside the response's body
	serviceType3 := servicetypes.ServiceType{"s1", []string{"host1", "host2", "host3"}, []string{"x509", "oidc"}, "mock-api-key", "uuid1", "unknown", "2018-05-05T18:04:05Z"}
	_, err3 := DeprecatedMapX509ToAuthItem(serviceType3, b1, "host1", mockstore, cfg)

	suite.Equal(expM1, m1)

	suite.Nil(err1)
	suite.Equal("Internal Error: Some internal error", err2.Error())
	suite.Equal("Internal Error: The specified retrieval field: unknown was not found in the response body of the service type", err3.Error())
}

func TestMapX509Suite(t *testing.T) {
	suite.Run(t, new(MapX509Suite))
}
