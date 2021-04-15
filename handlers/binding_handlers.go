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

	vars := mux.Vars(r)

	// check the validity of the JSON
	if err = json.NewDecoder(r.Body).Decode(&binding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	binding.Name = vars["name"]

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

	// check if the authID flag has any value
	authID := r.URL.Query().Get("authID")
	if authID != "" {
		binding, err := bindings.FindBindingByAuthID(authID, serviceType.UUID, vars["host"], "x509", store)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		bindingsList = bindings.BindingList{
			Bindings: []bindings.Binding{
				binding,
			},
		}

		utils.RespondOk(w, 200, bindingsList)
		return
	}

	if bindingsList, err = bindings.FindBindingsByServiceTypeAndHost(serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, bindingsList)

}

// BindingListOneByName finds and returns information about a binding, associated with the provided name
func BindingListOneByName(w http.ResponseWriter, r *http.Request) {

	var err error
	var binding bindings.Binding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	if binding, err = bindings.FindBindingByUUIDAndName("", vars["name"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, binding)

}

// BindingUpdate updates a binding
func BindingUpdate(w http.ResponseWriter, r *http.Request) {

	var err error
	var originalBinding bindings.Binding
	var updatedBinding bindings.Binding
	var tempBinding bindings.TempUpdateBinding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	if originalBinding, err = bindings.FindBindingByUUIDAndName("", vars["name"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	// first, fill the temporary binding with the fields of the original binding
	if err := utils.CopyFields(originalBinding, &tempBinding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(w, err)
	}

	// check the validity of the JSON and updated the provided fields
	if err = json.NewDecoder(r.Body).Decode(&tempBinding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(w, err)
		return
	}

	if updatedBinding, err = bindings.UpdateBinding(originalBinding, tempBinding, store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 200, updatedBinding)

}

// BindingDelete finds and deletes a binding using its UUID
func BindingDelete(w http.ResponseWriter, r *http.Request) {

	var err error
	var resourceBinding bindings.Binding

	//context references
	store := context.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the binding exists
	if resourceBinding, err = bindings.FindBindingByUUIDAndName("", vars["name"], store); err != nil {
		utils.RespondError(w, err)
		return
	}

	if err = bindings.DeleteBinding(resourceBinding, store); err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondOk(w, 204, nil)
}
