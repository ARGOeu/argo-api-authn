package handlers

import (
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/auth-methods"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"net/http"
)

func AuthMethodCreate(w http.ResponseWriter, r *http.Request) {

	var err error
	var authM map[string]interface{}
	var serviceType servicetypes.ServiceType
	var ok bool
	var flag bool
	var typeM string
	var i interface{}

	//context references
	store := context.Get(r, "stores").(stores.Store)
	cfg := context.Get(r, "config").(config.Config)

	// check the validity of the JSON
	if err = json.NewDecoder(r.Body).Decode(&authM); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	if len(authM) == 0 {
		err = utils.APIErrInvalidFieldContent("all fields", "Empty request body")
		utils.RespondError(w, err)
		return
	}

	// required variables for every type of auth method
	if i, ok = authM["type"]; ok == false {
		err = utils.APIErrEmptyRequiredField("Type was not found in the request body")
		utils.RespondError(w, err)
		return
	}
	typeM = i.(string)

	// check if the type is supported
	flag = false
	for _, am := range cfg.SupportedAuthMethods {
		if am == typeM {
			flag = true
			break
		}
	}
	if !flag {
		err = utils.APIErrInvalidFieldContent("type", typeM+" is not yet supported by the serviceType")
		utils.RespondError(w, err)
		return
	}

	if _, ok = authM["service_uuid"]; ok == false {
		err = utils.APIErrEmptyRequiredField("ServiceType UUID was not found in the request body")
		utils.RespondError(w, err)
		return
	}

	if _, ok = authM["host"]; ok == false {
		err = utils.APIErrEmptyRequiredField("Host was not found in the request body")
		utils.RespondError(w, err)
		return
	}

	if _, ok = authM["port"]; ok == false {
		err = utils.APIErrEmptyRequiredField("Port was not found in the request body")
		utils.RespondError(w, err)
		return
	}

	if _, ok = authM["path"]; ok == false {
		err = utils.APIErrEmptyRequiredField("Path was not found in the request body")
		utils.RespondError(w, err)
		return
	}

	// check if the serviceType exists
	if serviceType, err = servicetypes.FindServiceTypeByUUID(authM["service_uuid"].(string), store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the host exists
	if !serviceType.HasHost(authM["host"].(string)) {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	// check if the serviceType supports this kind of auth method
	if serviceType.AuthMethod != typeM {
		err = utils.APIErrUnsupportedContent("type", typeM)
		utils.RespondError(w, err)
		return
	}

	// checks if the serviceType on the given host has already an auth method declared
	// use the appropriate finder for the type of auth method
	authMFinder := auth_methods.AuthMethodFinders[typeM]

	if _, err := authMFinder(authM["service_uuid"].(string), authM["host"].(string), store); err == nil {
		err = utils.APIErrConflict(auth_methods.AuthMethod{}, "serviceType", authM["service_uuid"].(string))
		utils.RespondError(w, err)
		return
	}
	// find the appropriate creator method
	authMCreator := auth_methods.AuthMethodCreators[typeM]
	if authM, err = authMCreator(authM, store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// if everything went ok, reflect the created object
	utils.RespondOk(w, 201, authM)
}

func AuthMethodListOne(w http.ResponseWriter, r *http.Request) {

	var err error
	var authM map[string]interface{}
	var service servicetypes.ServiceType

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if service, err = servicetypes.FindServiceTypeByName(vars["service"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the host exists
	if !service.HasHost(vars["host"]) {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	// depending on the service's declared auth method, grab the respective finder
	authMFinder := auth_methods.AuthMethodFinders[service.AuthMethod]

	if authM, err = authMFinder(service.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// if everything went ok, return the auth method
	utils.RespondOk(w, 200, authM)
}

func AuthMethodListAll(w http.ResponseWriter, r *http.Request) {

	var authMList auth_methods.AuthMethodsList
	var err error

	//context references
	store := context.Get(r, "stores").(stores.Store)

	if authMList, err = auth_methods.FindAllAuthMethods(store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, authMList)
}
