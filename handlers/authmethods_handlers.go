package handlers

import (
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/authmethods"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"net/http"
)

func AuthMethodCreate(w http.ResponseWriter, r *http.Request) {

	var err error
	var authM authmethods.AuthMethod
	var serviceType servicetypes.ServiceType

	//context references
	store := context.Get(r, "stores").(stores.Store)
	//cfg := context.Get(r, "config").(config.Config)

	// url vars
	vars := mux.Vars(r)

	// check if the service type exists
	if serviceType, err = servicetypes.FindServiceTypeByName(vars["service-type"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// use the auth method factory to create an auth method based on the declared field of the service type
	if authM, err = authmethods.NewAuthMethodFactory().Create(serviceType.AuthMethod); err != nil {
		utils.RespondError(w, err)
		return
	}

	// fill the auth method with the default values for its type (e.g. ams)
	if err = authM.SetDefaults(serviceType.Type); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check the validity of the JSON and fill the auth method object
	if err = json.NewDecoder(r.Body).Decode(&authM); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	// assign service uuid and auth method type after decoding the request so it cannot be overwritten
	if err = utils.SetFieldValueByName(authM, "ServiceUUID", serviceType.UUID); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(w, err)
		return
	}

	if err = utils.SetFieldValueByName(authM, "Type", serviceType.AuthMethod); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(w, err)
		return
	}

	// create it
	if err = authmethods.AuthMethodCreate(authM, store, serviceType.AuthMethod); err != nil {
		utils.RespondError(w, err)
		return
	}

	// if everything went ok, return the newly created auth method
	utils.RespondOk(w, 201, authM)
}
