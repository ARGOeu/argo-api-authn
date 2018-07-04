package handlers

import (
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/context"
	LOGGER "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

// WrapConfig handle wrapper to retrieve configuration
func WrapConfig(hfn http.HandlerFunc, store stores.Store, config *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		context.Set(r, "stores", store)
		context.Set(r, "config", *config)
		context.Set(r, "service_token", config.ServiceToken)
		hfn.ServeHTTP(w, r)

	})
}

//WrapAuth authorizes the user
func WrapAuth(hfn http.HandlerFunc, store stores.Store) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		urlQueryVars := r.URL.Query()
		serviceToken := context.Get(r, "service_token").(string)
		if urlQueryVars.Get("key") != serviceToken {
			err := utils.APIErrUnauthorized("Wrong Credentials")
			utils.RespondError(w, err)
			return
		}
		hfn.ServeHTTP(w, r)
	})
}

// WrapLog handle wrapper to apply Logging
func WrapLog(hfn http.Handler, name string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()

		hfn.ServeHTTP(w, r)

		LOGGER.Info(
			"ACCESS", "\t",
			r.Method, "\t",
			r.RequestURI, "\t",
			name, "\t",
			time.Since(start),
		)
	})
}
