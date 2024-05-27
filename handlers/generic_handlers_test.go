package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/version"
	"github.com/gorilla/mux"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type GenericHandlerSuite struct {
	suite.Suite
}

func (suite *GenericHandlerSuite) TestListVersionUnauthorised() {

	// set up cfg
	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	str := stores.Mockstore{}

	req, err := http.NewRequest("GET", "http://localhost:8080/v1/version", nil)
	if err != nil {
		log.Fatal(err)
	}

	expResp := `{
 "build_time": "%v",
 "golang": "%v",
 "compiler": "%v",
 "os": "%v",
 "architecture": "%v",
 "distro": "%v"
}`
	expResp = fmt.Sprintf(expResp, version.BuildTime, version.GO, version.Compiler,
		version.OS, version.Arch, version.Distro)

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/v1/version", WrapConfig(ListVersion, &str, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResp, w.Body.String())
}

func (suite *GenericHandlerSuite) TestListVersionAuthorised() {

	// set up cfg
	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	str := stores.Mockstore{}

	req, err := http.NewRequest("GET", "http://localhost:8080/v1/version?key=token", nil)
	if err != nil {
		log.Fatal(err)
	}

	expResp := `{
 "build_time": "%v",
 "golang": "%v",
 "compiler": "%v",
 "os": "%v",
 "architecture": "%v",
 "release": "%v",
 "distro": "%v"
}`
	expResp = fmt.Sprintf(expResp, version.BuildTime, version.GO, version.Compiler,
		version.OS, version.Arch, version.Release, version.Distro)

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/v1/version", WrapConfig(ListVersion, &str, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResp, w.Body.String())
}

func (suite *GenericHandlerSuite) TestHealthCheck() {

	// set up cfg
	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	str := stores.Mockstore{}

	req, err := http.NewRequest("GET", "http://localhost:8080/v1/health", nil)
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/v1/health", WrapConfig(ListVersion, &str, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
}

func TestGenericHandlerTestSuite(t *testing.T) {
	LOGGER.SetOutput(io.Discard)
	suite.Run(t, new(GenericHandlerSuite))
}
