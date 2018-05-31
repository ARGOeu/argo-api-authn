package handlers

import (
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"net/http"
)

func BindingCreate(w http.ResponseWriter, r *http.Request) {

	var err error

	//context references
	store := context.Get(r, "stores").(stores.Store)

	var binding bindings.Binding

	// check the validity of the JSON
	if err = json.NewDecoder(r.Body).Decode(&binding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	if binding, err = bindings.CreateBinding(binding, store); err != nil {
		utils.RespondError(w, err)
		return
	}
	utils.RespondOk(w, 201, binding)
}

// BindingListAll returns a list, containing the existing bindings in the service
func BindingListAll(w http.ResponseWriter, r *http.Request) {

	var err error
	var bindingsList bindings.BindingList

	//context references
	store := context.Get(r, "stores").(stores.Store)

	if bindingsList, err = bindings.FindAllBindings(store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, bindingsList)

}

// BindingListAllByServiceTypeAndHost returns a list, containing all the bindings under the specified host and service type
func BindingListAllByServiceTypeAndHost(w http.ResponseWriter, r *http.Request) {

	var err error
	var ok bool
	var bindingsList bindings.BindingList
	var serviceType servicetypes.ServiceType

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if serviceType, err = servicetypes.FindServiceTypeByName(vars["service-type"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the provided host is associated with the given service type
	if ok = serviceType.HasHost(vars["host"]); ok == false {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	if bindingsList, err = bindings.FindBindingsByServiceTypeAndHost(serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, bindingsList)

}

// BindingListOneByDN finds and returns information about a binding, using its dn, service type and host
func BindingListOneByDN(w http.ResponseWriter, r *http.Request) {

	var err error
	var ok bool
	var serviceType servicetypes.ServiceType
	var binding bindings.Binding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if serviceType, err = servicetypes.FindServiceTypeByName(vars["service-type"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the provided host is associated with the given service type
	if ok = serviceType.HasHost(vars["host"]); ok == false {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	if binding, err = bindings.FindBindingByDN(vars["dn"], serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, binding)

}

// BindingUpdate updates a binding
func BindingUpdate(w http.ResponseWriter, r *http.Request) {

	var err error
	var ok bool
	var serviceType servicetypes.ServiceType
	var originalBinding bindings.Binding
	var updatedBinding bindings.Binding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if serviceType, err = servicetypes.FindServiceTypeByName(vars["service-type"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the provided host is associated with the given service type
	if ok = serviceType.HasHost(vars["host"]); ok == false {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	if originalBinding, err = bindings.FindBindingByDN(vars["dn"], serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// copy the original binding and then change its contents
	updatedBinding = originalBinding

	// check the validity of the JSON
	if err = json.NewDecoder(r.Body).Decode(&updatedBinding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	if updatedBinding, err = bindings.UpdateBinding(originalBinding, updatedBinding, store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, updatedBinding)

}

// BindingDelete deletes the specified binding from the store
func BindingDelete(w http.ResponseWriter, r *http.Request) {

	var err error
	var ok bool
	var serviceType servicetypes.ServiceType
	var resourceBinding bindings.Binding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if serviceType, err = servicetypes.FindServiceTypeByName(vars["service-type"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// check if the provided host is associated with the given service type
	if ok = serviceType.HasHost(vars["host"]); ok == false {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(w, err)
		return
	}

	// check if the binding exists
	if resourceBinding, err = bindings.FindBindingByDN(vars["dn"], serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	if err = bindings.DeleteBinding(resourceBinding, store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 204, "")
}