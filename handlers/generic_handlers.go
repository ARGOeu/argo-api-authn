package handlers

import (
	"fmt"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/ARGOeu/argo-api-authn/version"
	"github.com/gorilla/context"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

// WrapConfig handle wrapper to retrieve configuration
func WrapConfig(hfn http.HandlerFunc, store stores.Store, config *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// clone the store
		tempStore := store.Clone()
		defer tempStore.Close()

		context.Set(r, "stores", tempStore)
		context.Set(r, "config", *config)
		context.Set(r, "service_token", config.ServiceToken)
		hfn.ServeHTTP(w, r)

	})
}

// WrapAuth authorizes the user
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

		log.WithFields(
			log.Fields{
				"type":            "request_log",
				"method":          r.Method,
				"path":            r.URL.Path,
				"action":          name,
				"processing_time": time.Since(start).String(),
			},
		).Info("")

	})
}

// ListVersion displays version information about the service
func ListVersion(w http.ResponseWriter, r *http.Request) {

	// Add content type header to the response
	contentType := "application/json"
	charset := "utf-8"
	w.Header().Add("Content-Type", fmt.Sprintf("%s; charset=%s", contentType, charset))

	v := version.Version{
		BuildTime: version.BuildTime,
		GO:        version.GO,
		Compiler:  version.Compiler,
		OS:        version.OS,
		Arch:      version.Arch,
		Distro:    version.Distro,
	}

	urlQueryVars := r.URL.Query()
	serviceToken := context.Get(r, "service_token").(string)
	// Show the api release only for authorised requests
	if urlQueryVars.Get("key") == serviceToken {
		v.Release = version.Release
	}

	utils.RespondOk(w, http.StatusOK, v)
}

// HealthCheck just returns when the service is up and running
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	utils.RespondOk(w, http.StatusOK, nil)
}
