package routing

import (
	"net/http"

	log "github.com/Sirupsen/logrus"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/handlers"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
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

		handler = handlers.WrapAuth(handler, store)

		handler = handlers.WrapConfig(handler, store, config)

		ar.Router.Methods(route.Method).
			PathPrefix("/v1").
			Path(route.Path).
			Handler(context.ClearHandler(handler))
	}

	log.Info("API", "\t", "API Router initialized! Ready to start listening...")

	// Return reference to API object
	return &ar
}

var ApiRoutes = []APIRoute{
	{"serviceTypes:create", "POST", "/service-types", handlers.ServiceTypeCreate},
	{"serviceTypes:ListOne", "GET", "/service-types/{service-type}", handlers.ServiceTypesListOne},
	{"serviceType:ListAll", "GET", "/service-types", handlers.ServiceTypeListAll},
	{"authMethod:ListOne", "GET", "/service-types/{service-type}/hosts/{host}/authM", handlers.AuthMethodListOne},
	{"bindings:ListAllByServiceTypeAndHost", "GET", "/service-types/{service-type}/hosts/{host}/bindings", handlers.BindingListAllByServiceTypeAndHost},
	{"bindings:ListOneByDN", "GET", "/service-types/{service-type}/hosts/{host}/bindings/{dn}", handlers.BindingListOneByDN},
	{"bindings:update", "PATCH", "/service-types/{service-type}/hosts/{host}/bindings/{dn}", handlers.BindingUpdate},
	{"bindings:delete", "DELETE", "/service-types/{service-type}/hosts/{host}/bindings/{dn}", handlers.BindingDelete},
	{"authMethod:ListAll", "GET", "/authM", handlers.AuthMethodListAll},
	{"authMethod:Create", "POST", "/authM", handlers.AuthMethodCreate},
	{"bindings:create", "POST", "/bindings", handlers.BindingCreate},
	{"bindings:ListAll", "GET", "/bindings", handlers.BindingListAll},
	//{"auth:dn", "GET", "/auth/{service}/{host}/x509", handlers.AuthViaCert},
}
