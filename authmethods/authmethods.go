package authmethods

import (
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/satori/go.uuid"
	LOGGER "github.com/sirupsen/logrus"
)

var ApiKeyAuthMethodsPaths = map[string]string{
	"ams": "/v1/users:byUUID/{{identifier}}?key={{access_key}}",
}

var AuthMethodsRetrievalFields = map[string]string{
	"ams": "token",
}

type AuthMethodInit func() AuthMethod

var AuthMethodsTypes = map[string]AuthMethodInit{
	"api-key": NewApiKeyAuthMethod,
}

// A function type that refers to all the query functions for all the respective tuh method types
type QueryAuthMethodFinder func(serviceUUID string, host string, store stores.Store) ([]stores.QAuthMethod, error)

var QueryAuthMethodFinders = map[string]QueryAuthMethodFinder{
	"api-key": ApiKeyAuthFinder,
}

type AuthMethod interface {
	Validate(store stores.Store) error
	SetDefaults(tp string) error
}

// AuthMethodConvertToQueryModel converts an auth method to a query auth method
func AuthMethodConvertToQueryModel(fromAM AuthMethod, toType string) (stores.QAuthMethod, error) {

	var err error
	var qAuthMethod stores.QAuthMethod
	var authMethodBytes []byte

	// use the query auth method factory
	qamf := &stores.QAuthMethodFactory{}
	if qAuthMethod, err = qamf.Create(toType); err != nil {
		return qAuthMethod, err
	}

	// convert the auth method to bytes
	if authMethodBytes, err = json.Marshal(fromAM); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return qAuthMethod, err
	}

	// load the query model with the byte slice
	if err = json.Unmarshal(authMethodBytes, qAuthMethod); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return qAuthMethod, err
	}

	return qAuthMethod, err

}

// QueryModelConvertToAuthMethod converts a query auth method to an auth method
func QueryModelConvertToAuthMethod(fromQam stores.QAuthMethod, toType string) (AuthMethod, error) {

	var err error
	var authMethod AuthMethod
	var qAuthMethodBytes []byte

	// use the query auth method factory
	if authMethod, err = NewAuthMethodFactory().Create(toType); err != nil {
		return authMethod, err
	}

	// convert the query auth method to bytes
	if qAuthMethodBytes, err = json.Marshal(fromQam); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return authMethod, err
	}

	// load the auth method with the byte slice
	if err = json.Unmarshal(qAuthMethodBytes, authMethod); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return authMethod, err
	}

	return authMethod, err

}

// AuthMethodFinder uses the appropriate finder to search for a specific type of auth methods
func AuthMethodFinder(serviceUUID string, host string, authMethodType string, store stores.Store) (AuthMethod, error) {

	var err error
	var qAuthMs []stores.QAuthMethod
	var am AuthMethod
	var ok bool
	var finderFunc QueryAuthMethodFinder

	// access the appropriate finder based on the auth method type
	if finderFunc, ok = QueryAuthMethodFinders[authMethodType]; !ok {
		err = utils.APIGenericInternalError("Type is supported but not found")
		LOGGER.Errorf("Type: %v was used to retrieve from AuthMethodsRetrievalFields, but was not found inside the source code(QueryAuthMethodFinders) of despite being supported", authMethodType)
		return am, err
	}

	// execute the finder function
	if qAuthMs, err = finderFunc(serviceUUID, host, store); err != nil {
		return am, err
	}

	if len(qAuthMs) == 0 {
		err := utils.APIErrNotFound("Auth method")
		return am, err
	}

	if len(qAuthMs) > 1 {
		err := utils.APIGenericInternalError("More than 1 auth methods found for the given service type and host")
		return am, err
	}

	// convert the query model to an auth method
	if am, err = QueryModelConvertToAuthMethod(qAuthMs[0], "api-key"); err != nil {
		return am, err
	}

	return am, err

}

// AuthMethodAlreadyExists checks where or not any type of auth method already exists for the given host and service type
func AuthMethodAlreadyExists(serviceUUID string, host string, authMethodType string, store stores.Store) error {

	var err error

	_, err = AuthMethodFinder(serviceUUID, host, authMethodType, store)

	// if the err is nil, it means it found an already existing auth method
	if err == nil {
		err = utils.APIErrConflict("Auth method", "host", host)
		return err
	}

	// if the error
	if err.Error() != "Auth method was not found" {
		return err
	}

	return nil
}

// AuthMethodCreate inserts the given auth method to the datastore after performing some checks and enriching its contents
func AuthMethodCreate(am AuthMethod, store stores.Store, typeOfAuthMethod string) error {

	var err error
	var qAuthM stores.QAuthMethod

	var isu interface{}
	var ih interface{}

	// validate the auth method
	if err = am.Validate(store); err != nil {
		return err
	}

	if isu, err = utils.GetFieldValueByName(am, "ServiceUUID"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return err
	}

	if ih, err = utils.GetFieldValueByName(am, "Host"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return err
	}

	// check if an auth method already exists
	if err = AuthMethodAlreadyExists(isu.(string), ih.(string), typeOfAuthMethod, store); err != nil {
		return err
	}

	if err = utils.SetFieldValueByName(am, "UUID", uuid.NewV4().String()); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return err
	}

	if err = utils.SetFieldValueByName(am, "CreatedOn", utils.ZuluTimeNow()); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return err
	}

	if qAuthM, err = AuthMethodConvertToQueryModel(am, typeOfAuthMethod); err != nil {
		return err
	}

	if err = store.InsertAuthMethod(qAuthM); err != nil {
		return err
	}

	return err
}
