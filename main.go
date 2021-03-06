package main

import (
	"net/http"

	"github.com/gorilla/handlers"

	"flag"

	"crypto/tls"

	"strconv"

	"github.com/ARGOeu/argo-api-authn/auth"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/routing"
	"github.com/ARGOeu/argo-api-authn/stores"
	LOGGER "github.com/sirupsen/logrus"
)

func init() {
	LOGGER.SetFormatter(&LOGGER.TextFormatter{FullTimestamp: true, DisableColors: true})
}

func main() {

	// Retrieve configuration file location through cmd argument
	var cfgPath = flag.String("config", "/etc/argo-api-authn/conf.d/argo-api-authn-config.json", "Path for the required configuration file.")
	flag.Parse()

	// initialize the config
	var cfg = &config.Config{}
	if err := cfg.ConfigSetUp(*cfgPath); err != nil {
		LOGGER.Error(err.Error())
		panic(err.Error())
	}

	//configure datastore
	store := &stores.MongoStore{
		Server:   cfg.MongoHost,
		Database: cfg.MongoDB,
	}
	store.SetUp()

	defer store.Close()

	// configure the TLS config for the server
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,
		ClientAuth: cfg.ClientAuthPolicy(),
		ClientCAs:  auth.LoadCAs(cfg.CertificateAuthorities),
	}

	api := routing.NewRouting(routing.ApiRoutes, store, cfg)

	xReqWithConType := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-AuthModel"})
	allowVerbs := handlers.AllowedMethods([]string{"OPTIONS", "POST", "GET", "PUT", "DELETE", "HEAD"})

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(cfg.ServicePort),
		Handler:   handlers.CORS(xReqWithConType, allowVerbs)(api.Router),
		TLSConfig: tlsConfig,
	}

	//Start the server
	err := server.ListenAndServeTLS(cfg.Certificate, cfg.CertificateKey)
	if err != nil {
		LOGGER.Fatal("API", "\t", "ListenAndServe:", err)
	}
}
