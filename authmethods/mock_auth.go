package authmethods

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/mux"
	LOGGER "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httptest"
)

type ExternalServiceHandler func(w http.ResponseWriter, r *http.Request)

type QMockAuthMethod struct {
	RetrievalField string `json:"retrieval_field"`
}

func (m *QMockAuthMethod) Uuid() string {
	return "uuid"
}

type MockAuthMethod struct {
	RetrievalField string `json:"retrieval_field"`
}

func NewMockAuthMethod() AuthMethod {
	return new(MockAuthMethod)
}

func (m *MockAuthMethod) Validate(ctx context.Context, store stores.Store) error {
	return nil
}

func (m *MockAuthMethod) SetDefaults(tp string) error {
	return nil
}

func (m *MockAuthMethod) Update(r io.ReadCloser) (AuthMethod, error) {
	return nil, nil
}

func (m *MockAuthMethod) RetrieveAuthResource(ctx context.Context, binding bindings.Binding, serviceType servicetypes.ServiceType, cfg *config.Config) (map[string]interface{}, error) {

	var resp *http.Response
	var err error
	var ok bool
	var externalResp map[string]interface{}
	var externalHandler ExternalServiceHandler
	var authResource interface{}
	var retrievalField string

	if retrievalField, ok = cfg.ServiceTypesRetrievalFields[serviceType.Type]; !ok {
		err = utils.APIGenericInternalError("Backend error")
		LOGGER.Errorf("The retrieval field for type: %v was not found in the config retrieval fields: %v", serviceType.Type, cfg.ServiceTypesRetrievalFields)
		return externalResp, err
	}

	if externalHandler, ok = ExternalServiceHandlers[binding.UniqueKey]; !ok {
		err = utils.APIGenericInternalError("Backend error")
		return externalResp, err
	}

	// mock the request that will take place against the given service type
	resp, _ = MockRequestDispatcher(externalHandler)

	// evaluate the response
	if resp.StatusCode >= 400 {
		// convert the entire response body into a string and include into a genericAPIError
		buf := bytes.Buffer{}
		buf.ReadFrom(resp.Body)
		err = utils.APIGenericInternalError(buf.String())
		return externalResp, err
	}

	// get the response from the service type
	if err = json.NewDecoder(resp.Body).Decode(&externalResp); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return externalResp, err
	}

	defer resp.Body.Close()

	// check if the retrieval field that we need is present in the response
	if authResource, ok = externalResp[retrievalField]; !ok {
		err = utils.APIGenericInternalError(fmt.Sprintf("The specified retrieval field: `%v` was not found in the response body of the service type", m.RetrievalField))
		return externalResp, err
	}

	// if everything went ok, return the appropriate response field
	return map[string]interface{}{"token": authResource}, err
}

// MockKeyAuthFinder returns a MockAuthMethod for testing purposes
func MockKeyAuthFinder(ctx context.Context, serviceUUID string, host string, store stores.Store) ([]stores.QAuthMethod, error) {

	var err error
	var qAms []stores.QAuthMethod

	qMockAm := &QMockAuthMethod{RetrievalField: "token"}

	qAms = append(qAms, qMockAm)

	return qAms, err
}

// ExternalServiceHandlers contains mock handlers that represent various possible scenarios when executing requests to external services
var ExternalServiceHandlers = map[string]ExternalServiceHandler{
	"success":                   ExternalServiceHandlerSuccess,
	"incorrect-retrieval-field": ExternalServiceHandlerIncorrectRetrievalField,
}

// ExternalServiceHandlerSuccess mocks the behavior of a service type endpoint and returns a response containing the requested resource
func ExternalServiceHandlerSuccess(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("{\"token\": \"some-value\"}"))
}

// ExternalServiceHandlerIncorrectRetrievalField mocks the behavior of a successful external request that didn't contain the registered retrieval field
func ExternalServiceHandlerIncorrectRetrievalField(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
	w.Write([]byte("The specified retrieval field: incorrect_field was not found in the response body of the service type"))
}

// MockRequestDispatcher executes and captures the response of a mock handler
func MockRequestDispatcher(handler ExternalServiceHandler) (*http.Response, error) {

	var req2 *http.Request
	var err error

	if req2, err = http.NewRequest("GET", "http://localhost:8080/some_endpoint", nil); err != nil {
		LOGGER.Error(err.Error())
	}
	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/some_endpoint", handler)
	router.ServeHTTP(w, req2)
	return w.Result(), err

}
