package auth_methods

import (
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"net/http"
)

type AuthMethod struct{}

type AuthMethodsList struct {
	AuthMethods []map[string]interface{} `json:"auth_methods"`
}

type AuthMethodCreator func(authM map[string]interface{}, store stores.Store) (map[string]interface{}, error)

type AuthMethodFinder func(serviceUUID string, host string, store stores.Store) (map[string]interface{}, error)

type AuthMethodHandler func(data map[string]interface{}, store stores.Store, config *config.Config) (*http.Response, error)

var AuthMethodFinders = map[string]AuthMethodFinder{
	"api-key": FindApiKeyAuthMethod,
}

var AuthMethodCreators = map[string]AuthMethodCreator{
	"api-key": CreateApiKeyAuthMethod,
}

var AuthMethodHandlers = map[string]AuthMethodHandler{
	"api-key": ApiKeyAuthMethodHandler,
}

func FindAllAuthMethods(store stores.Store) (AuthMethodsList, error) {

	var err error
	var authMs = []map[string]interface{}{}

	if authMs, err = store.DeprecatedQueryAuthMethods("", "", ""); err != nil {
		return AuthMethodsList{AuthMethods: authMs}, err
	}

	return AuthMethodsList{AuthMethods: authMs}, err

}

// DeprecatedDeleteAuthMethod deletes the auth method associated with the provided service type
func DeleteAuthMethod(serviceUUID string, host string, typeName string, store stores.Store) error {

	var err error
	var authMs []map[string]interface{}

	if authMs, err = store.DeprecatedQueryAuthMethods(serviceUUID, host, typeName); err != nil {
		return err
	}

	// check if there is an auth method registered for the given service type and host
	if len(authMs) == 0 {
		err := utils.APIErrNotFound("Auth method")
		return err
	}

	// check if there is an internal conflict
	if len(authMs) > 1 {
		err = utils.APIErrDatabase("More than 1 auth methods found under the service type: " + serviceUUID + " and host: " + host)
		return err
	}

	if err = store.DeprecatedDeleteAuthMethod(authMs[0]); err != nil {
		return err
	}

	return err

}
