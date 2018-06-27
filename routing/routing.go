package routing

import (
	"net/http"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/handlers"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	LOGGER "github.com/sirupsen/logrus"
)

// API Object that holds routing information and the router itself
type API struct {
	Router *mux.Router // router Object reference
	Routes []APIRoute  // routes definitions list
}

// APIRoute Item describing an API route
type APIRoute struct {
	Name    string           // name of the route for description purposes
	Method  string           // GET, POST, PUT string literals
	Path    string           // API call path with urlVars included
	Handler http.HandlerFunc // Handler Function to be used
	Auth    bool             // whether or not it should use the auth handler
}

// NewRouting creates a new routing object including mux.Router and routes definitions
func NewRouting(routes []APIRoute, store stores.Store, config *config.Config) *API {
	// Create the api Object
	ar := API{}
	// Create a new router and reference him in API object
	ar.Router = mux.NewRouter().StrictSlash(false)
	// reference routes input in API object too keep info centralized
	ar.Routes = routes

	// For each route
	for _, route := range ar.Routes {

		// prepare handle wrappers
		var handler http.HandlerFunc

		handler = route.Handler

		handler = handlers.WrapLog(handler, route.Name)

		//  skip the auth handler for the requests that don't require authorization
		if route.Auth {
			handler = handlers.WrapAuth(handler, store)
		}

		handler = handlers.WrapConfig(handler, store, config)

		ar.Router.Methods(route.Method).
			PathPrefix("/v1").
			Path(route.Path).
			Handler(context.ClearHandler(handler))
	}

	LOGGER.Info("API", "\t", "API Router initialized! Ready to start listening...")

	// Return reference to the API object
	return &ar
}

var ApiRoutes = []APIRoute{
	{"serviceTypes:create", "POST", "/service-types", handlers.ServiceTypeCreate, true},
	{"serviceTypes:ListOne", "GET", "/service-types/{service-type}", handlers.ServiceTypesListOne, true},
	{"serviceTypes:ListOne", "PUT", "/service-types/{service-type}", handlers.ServiceTypeUpdate, true},
	{"serviceType:ListAll", "GET", "/service-types", handlers.ServiceTypeListAll, true},
	{"authMethod:ListOne", "GET", "/service-types/{service-type}/hosts/{host}/authM", handlers.DeprecatedAuthMethodListOne, true},
	{"authMethod:Delete", "DELETE", "/service-types/{service-type}/hosts/{host}/authM", handlers.DeprecatedAuthMethodDelete, true},
	{"bindings:ListAllByServiceTypeAndHost", "GET", "/service-types/{service-type}/hosts/{host}/bindings", handlers.BindingListAllByServiceTypeAndHost, true},
	{"bindings:ListOneByDN", "GET", "/service-types/{service-type}/hosts/{host}/bindings/{dn}", handlers.BindingListOneByDN, true},
	{"authMethod:ListAll", "GET", "/authM", handlers.DeprecatedAuthMethodListAll, true},
	{"authMethod:Create", "POST", "/authM", handlers.DeprecatedAuthMethodCreate, true},
	{"bindings:create", "POST", "/bindings", handlers.BindingCreate, true},
	{"bindings:ListAll", "GET", "/bindings", handlers.BindingListAll, true},
	{"bindings:update", "PUT", "/bindings/{uuid}", handlers.BindingUpdate, true},
	{"bindings:ListOneByUUID", "GET", "/bindings/{uuid}", handlers.BindingListOneByUUID, true},
	{"bindings:delete", "DELETE", "/bindings/{uuid}", handlers.BindingDelete, true},
	{"auth:dn", "GET", "/service-types/{service-type}/hosts/{host}:authX509", handlers.DeprecatedAuthViaCert, false},
}
