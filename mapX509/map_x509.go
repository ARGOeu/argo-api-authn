package mapX509

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ARGOeu/argo-api-authn/auth-methods"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"net/http"
)

// Deprecated:
func DeprecatedMapX509ToAuthItem(serviceType servicetypes.ServiceType, binding bindings.Binding, host string, store stores.Store, config *config.Config) (map[string]interface{}, error) {

	var err error
	var ok bool
	var dataRes map[string]interface{}
	var resp *http.Response
	var rf interface{}

	// retrieve the auth method handler corresponding to the given serviceType's auth type
	var data = map[string]interface{}{"service_uuid": serviceType.UUID, "host": host, "unique_key": binding.UniqueKey}
	authFunc := auth_methods.AuthMethodHandlers[serviceType.AuthMethod]
	if resp, err = authFunc(data, store, config); err != nil {
		return dataRes, err
	}

	if resp.StatusCode >= 400 {
		// convert the entire response body into a string and include into a genericAPIError
		buf := bytes.Buffer{}
		buf.ReadFrom(resp.Body)
		err = utils.APIGenericInternalError(buf.String())
		return dataRes, err
	}

	// get the response from the service type
	if err = json.NewDecoder(resp.Body).Decode(&dataRes); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return dataRes, err
	}

	defer resp.Body.Close()

	// check if the retrieval field that we need is present in the response
	if rf, ok = dataRes["token"]; !ok {
		err = utils.APIGenericInternalError(fmt.Sprintf(`The specified retrieval field: %v was not found in the response body of the service type`, "token"))
		return dataRes, err
	}

	// if everything went ok, return the appropriate response field
	return map[string]interface{}{"token": rf.(string)}, err

}
