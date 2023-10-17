package authmethods

import (
	"context"
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io"
)

type AuthMethodInit func() AuthMethod

var AuthMethodsTypes = map[string]AuthMethodInit{
	"api-key": NewApiKeyAuthMethod,
	"headers": NewHeadersAuthMethod,
}

// QueryAuthMethodFinder is a function type that refers to all the query functions for all the respective auth method types
type QueryAuthMethodFinder func(ctx context.Context, serviceUUID string, host string, store stores.Store) ([]stores.QAuthMethod, error)

var QueryAuthMethodFinders = map[string]QueryAuthMethodFinder{
	"api-key": ApiKeyAuthFinder,
	"headers": HeadersAuthFinder,
}

type AuthMethod interface {
	Validate(ctx context.Context, store stores.Store) error
	Update(r io.ReadCloser) (AuthMethod, error)
	RetrieveAuthResource(ctx context.Context, binding bindings.Binding, serviceType servicetypes.ServiceType, cfg *config.Config) (map[string]interface{}, error)
}

type AuthMethodsList struct {
	AuthMethods []AuthMethod `json:"auth_methods"`
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
func QueryModelConvertToAuthMethod(ctx context.Context, fromQam stores.QAuthMethod, toType string) (AuthMethod, error) {

	var err error
	var authMethod AuthMethod
	var qAuthMethodBytes []byte

	// use the query auth method factory
	if authMethod, err = NewAuthMethodFactory().Create(ctx, toType); err != nil {
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
func AuthMethodFinder(ctx context.Context, serviceUUID string, host string, authMethodType string, store stores.Store) (AuthMethod, error) {

	var err error
	var qAuthMs []stores.QAuthMethod
	var am AuthMethod
	var ok bool
	var finderFunc QueryAuthMethodFinder

	// access the appropriate finder based on the auth method type
	if finderFunc, ok = QueryAuthMethodFinders[authMethodType]; !ok {
		err = utils.APIGenericInternalError("Type is supported but not found")
		log.WithFields(
			log.Fields{
				"trace_id": ctx.Value("trace_id"),
				"type":     "service_log",
			},
		).Errorf("Type: %v was used to retrieve from AuthMethodsRetrievalFields,"+
			" but was not found inside the source code(QueryAuthMethodFinders) of despite being supported", authMethodType)
		return am, err
	}

	// execute the finder function
	if qAuthMs, err = finderFunc(ctx, serviceUUID, host, store); err != nil {
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
	if am, err = QueryModelConvertToAuthMethod(ctx, qAuthMs[0], authMethodType); err != nil {
		return am, err
	}

	return am, err

}

// AuthMethodAlreadyExists checks where or not any type of auth method already exists for the given host and service type
func AuthMethodAlreadyExists(ctx context.Context, serviceUUID string, host string, authMethodType string, store stores.Store) error {

	var err error

	_, err = AuthMethodFinder(ctx, serviceUUID, host, authMethodType, store)

	// if the err is nil, it means it found an already existing auth method
	if err == nil {
		err = utils.APIErrConflict("Auth method", "host", host)
		return err
	}

	// if there is any other error, treat it as a normal error
	if err.Error() != "Auth method was not found" {
		return err
	}

	return nil
}

// AuthMethodCreate inserts the given auth method to the datastore after performing some checks and enriching its contents
func AuthMethodCreate(ctx context.Context, am AuthMethod, store stores.Store, typeOfAuthMethod string) error {

	var err error
	var qAuthM stores.QAuthMethod

	var isu interface{}
	var ih interface{}

	// validate the auth method
	if err = am.Validate(ctx, store); err != nil {
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
	if err = AuthMethodAlreadyExists(ctx, isu.(string), ih.(string), typeOfAuthMethod, store); err != nil {
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

	if err = store.InsertAuthMethod(ctx, qAuthM); err != nil {
		return err
	}

	return err
}

// AuthMethodFindAll finds and returns all the registered auth methods
func AuthMethodFindAll(ctx context.Context, store stores.Store) (AuthMethodsList, error) {

	var err error
	var am AuthMethod
	var qams []stores.QAuthMethod

	var amList = AuthMethodsList{AuthMethods: []AuthMethod{}}

	// loop through all the finders and aggregate their results
	for amType, finderFunc := range QueryAuthMethodFinders {
		if qams, err = finderFunc(ctx, "", "", store); err != nil {
			return amList, err
		}

		// if there is no error convert the query auth methods to auth methods
		for _, qam := range qams {

			// convert the query model to an auth method
			if am, err = QueryModelConvertToAuthMethod(ctx, qam, amType); err != nil {
				return amList, err
			}
			// if there is no error, append the converted auth method to the slice
			amList.AuthMethods = append(amList.AuthMethods, am)
		}
	}

	return amList, err

}

// AuthMethodDelete deletes the given auth method from the data store
func AuthMethodDelete(ctx context.Context, am AuthMethod, store stores.Store) error {

	var err error
	var qam stores.QAuthMethod
	var iType interface{}

	// grab the type of the provided auth method
	if iType, err = utils.GetFieldValueByName(am, "Type"); err != nil {
		return err
	}

	// convert the auth method to its respective query model
	if qam, err = AuthMethodConvertToQueryModel(am, iType.(string)); err != nil {
		return err
	}

	// delete the query auth method
	if err = store.DeleteAuthMethod(ctx, qam); err != nil {
		return err
	}

	return err
}

// AuthMethodUpdate updates the given method with a reader's data
func AuthMethodUpdate(ctx context.Context, am AuthMethod, r io.ReadCloser, store stores.Store) (AuthMethod, error) {

	var err error
	var updatedAm AuthMethod
	var qOriginalAm stores.QAuthMethod
	var qUpdatedAm stores.QAuthMethod
	var iType interface{}
	var iSuuidUpdated interface{}
	var iSuuidOriginal interface{}
	var iHostUpdated interface{}
	var iHostOriginal interface{}

	// grab the type of the provided auth method
	if iType, err = utils.GetFieldValueByName(am, "Type"); err != nil {
		return updatedAm, err
	}

	// update the given auth method
	if updatedAm, err = am.Update(r); err != nil {
		return updatedAm, err
	}

	// validate the updated auth method
	if err = updatedAm.Validate(ctx, store); err != nil {
		return updatedAm, err
	}

	// if serviceUUID and host have been modified , check if there is an auth method already present
	if iSuuidOriginal, err = utils.GetFieldValueByName(am, "ServiceUUID"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return updatedAm, err
	}

	if iSuuidUpdated, err = utils.GetFieldValueByName(updatedAm, "ServiceUUID"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return updatedAm, err
	}

	if iHostOriginal, err = utils.GetFieldValueByName(am, "Host"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return updatedAm, err
	}

	if iHostUpdated, err = utils.GetFieldValueByName(updatedAm, "Host"); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return updatedAm, err
	}

	if iSuuidUpdated != iSuuidOriginal || iHostUpdated != iHostOriginal {
		if err = AuthMethodAlreadyExists(ctx, iSuuidUpdated.(string), iHostUpdated.(string), iType.(string), store); err != nil {
			return updatedAm, err
		}
	}

	// convert the given and updated auth methods to their respective query models
	if qOriginalAm, err = AuthMethodConvertToQueryModel(am, iType.(string)); err != nil {
		return updatedAm, err
	}

	if qUpdatedAm, err = AuthMethodConvertToQueryModel(updatedAm, iType.(string)); err != nil {
		return updatedAm, err
	}

	// update the auth method
	if qUpdatedAm, err = store.UpdateAuthMethod(ctx, qOriginalAm, qUpdatedAm); err != nil {
		return updatedAm, err
	}

	return updatedAm, err

}
