package handlers

import (
	"context"
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	gorillaContext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	"net/http"
)

func BindingCreate(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	var binding bindings.Binding

	vars := mux.Vars(r)

	// check the validity of the JSON
	if err = json.NewDecoder(r.Body).Decode(&binding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(rCTX, w, err)
		return
	}

	binding.Name = vars["name"]

	if binding, err = bindings.CreateBinding(rCTX, binding, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}
	utils.RespondOk(w, 201, binding)
}

// BindingListAll returns a list, containing the existing bindings in the service
func BindingListAll(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var bindingsList bindings.BindingList

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	if bindingsList, err = bindings.FindAllBindings(rCTX, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	utils.RespondOk(w, 200, bindingsList)

}

// BindingListAllByServiceTypeAndHost returns a list, containing all the bindings under the specified host and service type
func BindingListAllByServiceTypeAndHost(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var bindingsList bindings.BindingList
	var serviceType servicetypes.ServiceType

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the service exists
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the provided host is associated with the given service type
	if ok := serviceType.HasHost(vars["host"]); !ok {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the authID flag has any value
	authID := r.URL.Query().Get("authID")
	if authID != "" {
		binding, err := bindings.FindBindingByAuthID(rCTX, authID, serviceType.UUID, vars["host"], "x509", store)
		if err != nil {
			utils.RespondError(rCTX, w, err)
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

	if bindingsList, err = bindings.FindBindingsByServiceTypeAndHost(rCTX, serviceType.UUID, vars["host"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	utils.RespondOk(w, 200, bindingsList)

}

// BindingListOneByName finds and returns information about a binding, associated with the provided name
func BindingListOneByName(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var binding bindings.Binding

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	if binding, err = bindings.FindBindingByUUIDAndName(rCTX, "", vars["name"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	utils.RespondOk(w, 200, binding)

}

// BindingUpdate updates a binding
func BindingUpdate(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var originalBinding bindings.Binding
	var updatedBinding bindings.Binding
	var tempBinding bindings.TempUpdateBinding

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	if originalBinding, err = bindings.FindBindingByUUIDAndName(rCTX, "", vars["name"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// first, fill the temporary binding with the fields of the original binding
	if err := utils.CopyFields(originalBinding, &tempBinding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		utils.RespondError(rCTX, w, err)
	}

	// check the validity of the JSON and updated the provided fields
	if err = json.NewDecoder(r.Body).Decode(&tempBinding); err != nil {
		err := utils.APIErrBadRequest(err.Error())
		utils.RespondError(rCTX, w, err)
		return
	}

	if updatedBinding, err = bindings.UpdateBinding(rCTX, originalBinding, tempBinding, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	utils.RespondOk(w, 200, updatedBinding)

}

// BindingDelete finds and deletes a binding using its UUID
func BindingDelete(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var resourceBinding bindings.Binding

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)

	// check if the binding exists
	if resourceBinding, err = bindings.FindBindingByUUIDAndName(rCTX, "", vars["name"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	if err = bindings.DeleteBinding(rCTX, resourceBinding, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	utils.RespondOk(w, 204, nil)
}
