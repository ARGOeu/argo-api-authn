package auth_methods

import (
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/Sirupsen/logrus"
)

type AuthMethod struct{}

type AuthMethodsList struct {
	AuthMethods []map[string]interface{} `json:"auth_methods"`
}

type AuthMethodCreator func(authM map[string]interface{}, store stores.Store) (map[string]interface{}, error)

type AuthMethodFinder func(serviceUUID string, host string, store stores.Store) (map[string]interface{}, error)

var AuthMethodFinders = map[string]AuthMethodFinder{
	"api-key": FindApiKeyAuthMethod,
}

var AuthMethodCreators = map[string]AuthMethodCreator{
	"api-key": CreateApiKeyAuthMethod,
}

func FindAllAuthMethods(store stores.Store) ([]map[string]interface{}, error) {

	var err error
	var authMs []map[string]interface{}

	if authMs, err = store.QueryAuthMethods("", "", ""); err != nil {
		return authMs, err
	}

	logrus.Info(authMs)

	return authMs, err

}
