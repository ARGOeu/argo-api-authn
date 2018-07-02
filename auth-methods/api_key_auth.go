package auth_methods

import (
	"crypto/tls"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func FindApiKeyAuthMethod(serviceUUID string, host string, store stores.Store) (map[string]interface{}, error) {

	var err error
	var apiKeyAuthMap map[string]interface{}
	var apiKeyAuthMaps []map[string]interface{}
	var ok bool

	if apiKeyAuthMaps, err = store.DeprecatedQueryAuthMethods(serviceUUID, host, "api-key"); err != nil {
		return apiKeyAuthMap, err
	}

	if len(apiKeyAuthMaps) == 0 {
		err = utils.APIErrNotFound("Auth method")
		return apiKeyAuthMap, err
	}

	// required variables
	if _, ok = apiKeyAuthMaps[0]["path"]; ok == false {
		err = utils.APIErrDatabase("Path was not found in the ApiKeyAuth object")
		return apiKeyAuthMap, err
	}

	if _, ok = apiKeyAuthMaps[0]["port"]; ok == false {
		err = utils.APIErrDatabase("Port was not found in the ApiKeyAuth object")
		return apiKeyAuthMap, err
	}

	if _, ok = apiKeyAuthMaps[0]["access_key"]; ok == false {
		err = utils.APIErrDatabase("Access Key was not found in the ApiKeyAuth object")
		return apiKeyAuthMap, err
	}

	return apiKeyAuthMaps[0], err
}

func CreateApiKeyAuthMethod(authM map[string]interface{}, store stores.Store) (map[string]interface{}, error) {

	var err error
	var ok bool

	// extra required variables
	if _, ok = authM["access_key"]; ok == false {
		err = utils.APIErrEmptyRequiredField("api-key-auth", "access_key was not found in the request body")
		return authM, err
	}

	// check if the path contains at least the two interpolations, {{identifier}}, {{access_key}}
	if !strings.Contains(authM["path"].(string), "{{identifier}}") {
		err = utils.APIErrInvalidFieldContent("path", "Doesn't contain {{identifier}}")
		return authM, err
	}

	if !strings.Contains(authM["path"].(string), "{{access_key}}") {
		err = utils.APIErrInvalidFieldContent("path", "Doesn't contain {{access_key}}")
		return authM, err
	}

	if err = store.DeprecatedInsertAuthMethod(authM); err != nil {
		return authM, err
	}

	return authM, err

}

// ApiKeyAuthMethodHandler performs the functionality that retrieves a resource from a service type that uses an api-key as an authentication method
func ApiKeyAuthMethodHandler(data map[string]interface{}, store stores.Store, config *config.Config) (*http.Response, error) {

	var authM map[string]interface{}
	var resourcePath string
	var resp *http.Response
	var err error

	if authM, err = FindApiKeyAuthMethod(data["service_uuid"].(string), data["host"].(string), store); err != nil {
		return resp, err
	}

	// build the path that identifies the resource we are going to request
	resourcePath = strings.Replace(authM["path"].(string), "{{identifier}}", data["unique_key"].(string), 1)
	resourcePath = strings.Replace(resourcePath, "{{access_key}}", authM["access_key"].(string), 1)

	// build the client and execute the request
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !config.VerifySSL},
	}
	client := &http.Client{Transport: transCfg, Timeout: time.Duration(30 * time.Second)}

	if resp, err = client.Get("https://" + data["host"].(string) + ":" + strconv.Itoa(int(authM["port"].(float64))) + resourcePath); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return resp, err
	}
	return resp, err
}
