package authmethods

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HeadersAuthMethod struct {
	BasicAuthMethod
	Headers map[string]string `json:"headers" required:"true"`
}

// TempHeadersAuthMethod  represents the fields that are allowed to be modified
type TempHeadersAuthMethod struct {
	TempBasicAuthMethod
	Headers map[string]string `json:"headers" required:"true"`
}

func NewHeadersAuthMethod() AuthMethod {
	return new(HeadersAuthMethod)
}

func (m *HeadersAuthMethod) Validate(ctx context.Context, store stores.Store) error {

	var err error

	// check if the embedded struct is valid
	if err = m.BasicAuthMethod.Validate(ctx, store); err != nil {
		return err
	}

	// check if all required field have been provided
	if err = utils.ValidateRequired(*m); err != nil {
		err := utils.APIErrEmptyRequiredField("auth method", err.Error())
		return err
	}

	// check that the headers map is not empty
	if len(m.Headers) == 0 {
		err := utils.APIErrEmptyRequiredField("auth method", utils.GenericEmptyRequiredField("headers").Error())
		return err
	}

	return err
}

func (m *HeadersAuthMethod) Update(r io.ReadCloser) (AuthMethod, error) {

	var err error
	var authMBytes []byte
	var tempAM TempHeadersAuthMethod

	var updatedAM = &HeadersAuthMethod{}

	// first fill the temp auth method with the already existing data
	// convert the existing auth method to bytes
	if authMBytes, err = json.Marshal(*m); err != nil {
		err := utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	// then load the bytes into the temp auth method
	if err = json.Unmarshal(authMBytes, &tempAM); err != nil {
		err := utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	// check the validity of the JSON and fill the temp auth method object with the updated data
	if err = json.NewDecoder(r).Decode(&tempAM); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		return updatedAM, err
	}

	// close the reader
	if err = r.Close(); err != nil {
		err := utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	// fill the updated auth method with the already existing data
	if err := utils.CopyFields(*m, updatedAM); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	// transfer the updated temporary data to the updated auth method object
	// in order to override the outdated fields
	// convert to bytes
	if authMBytes, err = json.Marshal(tempAM); err != nil {
		err := utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	// then load the bytes
	if err = json.Unmarshal(authMBytes, updatedAM); err != nil {
		err := utils.APIGenericInternalError(err.Error())
		return updatedAM, err
	}

	m.UpdatedOn = utils.ZuluTimeNow()
	return updatedAM, err
}

func (m *HeadersAuthMethod) RetrieveAuthResource(ctx context.Context, binding bindings.Binding, serviceType servicetypes.ServiceType, cfg *config.Config) (map[string]interface{}, error) {

	var externalResp map[string]interface{}
	var err error
	var ok bool
	var resp *http.Response
	var authResource interface{}
	var retrievalField string
	var path string

	if retrievalField, ok = cfg.ServiceTypesRetrievalFields[serviceType.Type]; !ok {
		err = utils.APIGenericInternalError("Backend error")
		log.WithFields(
			log.Fields{
				"trace_id":     ctx.Value("trace_id"),
				"type":         "service_log",
				"service_type": serviceType.Type,
				"fields":       cfg.ServiceTypesRetrievalFields,
			},
		).Error("Retrieval field for service-type was not found in service config")
		return externalResp, err
	}

	if path, ok = cfg.ServiceTypesPaths[serviceType.Type]; !ok {
		err = utils.APIGenericInternalError("Backend error")
		log.WithFields(
			log.Fields{
				"trace_id":     ctx.Value("trace_id"),
				"type":         "service_log",
				"service_type": serviceType.Type,
				"paths":        cfg.ServiceTypesPaths,
			},
		).Error("Path field for service-type was not found in service config")
		return externalResp, err
	}

	// build the path that identifies the resource we are going to request
	resourcePath := fmt.Sprintf("https://%v:%v%v", m.Host, strconv.Itoa(m.Port), path)
	resourcePath = strings.Replace(resourcePath, "{{identifier}}", binding.UniqueKey, 1)

	// build the client and execute the request
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}

	client := &http.Client{Transport: transCfg, Timeout: time.Duration(30 * time.Second)}

	req, err := http.NewRequest(http.MethodGet, resourcePath, nil)
	if err != nil {
		err = utils.APIGenericInternalError(err.Error())
	}

	// populate the request with the headers
	for k, v := range m.Headers {
		req.Header.Add(k, v)
	}

	resp, err = client.Do(req)
	if err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return externalResp, err
	}

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
		err = utils.APIGenericInternalError(fmt.Sprintf("The specified retrieval field: `%v` was not found in the response body of the service type", retrievalField))
		return externalResp, err
	}

	// if everything went ok, return the appropriate response field
	return map[string]interface{}{"token": authResource}, err

}

func HeadersAuthFinder(ctx context.Context, serviceUUID string, host string, store stores.Store) ([]stores.QAuthMethod, error) {

	var err error
	var qAms []stores.QAuthMethod
	var qApiAms []stores.QHeadersAuthMethod

	if qApiAms, err = store.QueryHeadersAuthMethods(ctx, serviceUUID, host); err != nil {
		return qAms, err
	}

	for _, apim := range qApiAms {
		qAms = append(qAms, &apim)
	}

	return qAms, err
}
