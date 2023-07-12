package handlers

import (
	"context"
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/authmethods"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	gorillaContext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	"net/http"
)

func AuthMethodCreate(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var authM authmethods.AuthMethod
	var serviceType servicetypes.ServiceType

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)
	//cfg := gorillaContext.Get(r, "config").(config.Config)

	// url vars
	vars := mux.Vars(r)

	// check if the service type exists
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// use the auth method factory to create an auth method based on the declared field of the service type
	if authM, err = authmethods.NewAuthMethodFactory().Create(rCTX, serviceType.AuthMethod); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check the validity of the JSON and fill the auth method object
	if err = json.NewDecoder(r.Body).Decode(&authM); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(rCTX, w, err)
		return
	}

	// assign service uuid and auth method type after decoding the request so it cannot be overwritten
	if err = utils.SetFieldValueByName(authM, "ServiceUUID", serviceType.UUID); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(rCTX, w, err)
		return
	}

	if err = utils.SetFieldValueByName(authM, "Type", serviceType.AuthMethod); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(rCTX, w, err)
		return
	}

	// create it
	if err = authmethods.AuthMethodCreate(rCTX, authM, store, serviceType.AuthMethod); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// if everything went ok, return the newly created auth method
	utils.RespondOk(w, 201, authM)
}

func AuthMethodListOne(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var ok bool
	var serviceType servicetypes.ServiceType
	var authm authmethods.AuthMethod

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service type exists
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the host is associated with the service type
	if ok = serviceType.HasHost(vars["host"]); !ok {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(rCTX, w, err)
		return
	}

	if authm, err = authmethods.AuthMethodFinder(rCTX, serviceType.UUID, vars["host"], serviceType.AuthMethod, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// if everything went ok return the auth method
	utils.RespondOk(w, 200, authm)

}

func AuthMethodListAll(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var amList authmethods.AuthMethodsList

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	if amList, err = authmethods.AuthMethodFindAll(rCTX, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// if everything went ok, return the list
	utils.RespondOk(w, 200, amList)

}

func AuthMethodDeleteOne(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var serviceType servicetypes.ServiceType
	var ok bool
	var authm authmethods.AuthMethod

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service type exists
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the host is associated with the service type
	if ok = serviceType.HasHost(vars["host"]); !ok {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the auth method exists
	if authm, err = authmethods.AuthMethodFinder(rCTX, serviceType.UUID, vars["host"], serviceType.AuthMethod, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	if err = authmethods.AuthMethodDelete(rCTX, authm, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// if everything went ok
	utils.RespondOk(w, 204, nil)
}

func AuthMethodUpdateOne(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var serviceType servicetypes.ServiceType
	var ok bool
	var authm authmethods.AuthMethod

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service type exists
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the host is associated with the service type
	if ok = serviceType.HasHost(vars["host"]); !ok {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the auth method exists
	if authm, err = authmethods.AuthMethodFinder(rCTX, serviceType.UUID, vars["host"], serviceType.AuthMethod, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	if authm, err = authmethods.AuthMethodUpdate(rCTX, authm, r.Body, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// if everything went ok
	utils.RespondOk(w, 200, authm)
}
