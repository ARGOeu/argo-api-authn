package authmethods

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	LOGGER "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ApiKeyAuthMethod struct {
	BasicAuthMethod
	AccessKey string `json:"access_key" required:"true"`
}

// TempApiKeyAuthMethod represents the fields that are allowed to be modified
type TempApiKeyAuthMethod struct {
	TempBasicAuthMethod
	AccessKey string `json:"access_key" required:"true"`
}

func NewApiKeyAuthMethod() AuthMethod {
	return new(ApiKeyAuthMethod)
}

func (m *ApiKeyAuthMethod) Validate(store stores.Store) error {

	var err error

	// check if the embedded struct is valid
	if err = m.BasicAuthMethod.Validate(store); err != nil {
		return err
	}

	// check if all required field have been provided
	if err = utils.ValidateRequired(*m); err != nil {
		err := utils.APIErrEmptyRequiredField("auth method", err.Error())
		return err
	}

	// check if the path contains at least the two interpolations, {{identifier}}, {{access_key}}
	if !strings.Contains(m.Path, "{{identifier}}") {
		err = utils.APIErrInvalidFieldContent("path", "Missing {{identifier}} interpolation")
		return err
	}

	if !strings.Contains(m.Path, "{{access_key}}") {
		err = utils.APIErrInvalidFieldContent("path", "Missing {{access_key}} interpolation")
		return err
	}

	return err
}

func (m *ApiKeyAuthMethod) SetDefaults(stp string) error {

	var err error
	var ok bool
	var val string

	// try to check if the service type that this auth method will belong to, has pre-defined settings
	if val, ok = AuthMethodsRetrievalFields[stp]; ok {
		m.RetrievalField = val
	} else {
		err = utils.APIGenericInternalError("Type is supported but not found")
		LOGGER.Errorf("Type: %v was used to retrieve from AuthMethodsRetrievalFields, but was not found inside the source code of despite being supported", stp)
		return err
	}

	if val, ok = ApiKeyAuthMethodsPaths[stp]; ok {
		m.Path = val
	} else {
		err = utils.APIGenericInternalError("Type is supported but not found")
		LOGGER.Errorf("Type: %v was used to retrieve from ApiKeyAuthMethodsPaths, but was not found inside the source code of despite being supported", stp)
		return err
	}

	return err
}

func (m *ApiKeyAuthMethod) Update(r io.ReadCloser) (AuthMethod, error) {

	var err error
	var authMBytes []byte
	var tempAM TempApiKeyAuthMethod

	var updatedAM = NewApiKeyAuthMethod()

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

	return updatedAM, err
}

func (m *ApiKeyAuthMethod) RetrieveAuthResource(data map[string]interface{}, cfg *config.Config) (map[string]interface{}, error) {

	var externalResp map[string]interface{}
	var err error
	var ok bool
	var resp *http.Response
	var authResource interface{}
	var bindingInfo interface{}

	if bindingInfo, ok = data["binding-identifier"]; !ok {
		LOGGER.Errorf("Binding-identifier was not found in the provided map: %v", data)
		err = utils.APIGenericInternalError("Backend error")
		return externalResp, err
	}

	// build the path that identifies the resource we are going to request
	resourcePath := fmt.Sprintf("https://%v:%v%v", m.Host, strconv.Itoa(m.Port), m.Path)
	resourcePath = strings.Replace(resourcePath, "{{identifier}}", bindingInfo.(string), 1)
	resourcePath = strings.Replace(resourcePath, "{{access_key}}", m.AccessKey, 1)

	// build the client and execute the request
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}

	client := &http.Client{Transport: transCfg, Timeout: time.Duration(30 * time.Second)}

	if resp, err = client.Get(resourcePath); err != nil {
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
	if authResource, ok = externalResp[m.RetrievalField]; !ok {
		err = utils.APIGenericInternalError(fmt.Sprintf("The specified retrieval field: `%v` was not found in the response body of the service type", m.RetrievalField))
		return externalResp, err
	}

	// if everything went ok, return the appropriate response field
	return map[string]interface{}{"token": authResource}, err

}

func ApiKeyAuthFinder(serviceUUID string, host string, store stores.Store) ([]stores.QAuthMethod, error) {

	var err error
	var qAms []stores.QAuthMethod
	var qApiAms []stores.QApiKeyAuthMethod

	if qApiAms, err = store.QueryApiKeyAuthMethods(serviceUUID, host); err != nil {
		return qAms, err
	}

	for _, apim := range qApiAms {
		qAms = append(qAms, &apim)
	}

	return qAms, err
}
