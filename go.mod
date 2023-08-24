module github.com/ARGOeu/argo-api-authn

go 1.14

// testcontainers-go last possible compatible version with go1.14 is v0.14.0
// This version is compatible with go 1.13 thus we needed to modify the codebase to be compatible with 1.14
// As a result we need to keep the depedency within the project as a "custom module".
require github.com/testcontainers/testcontainers-go v0.14.0

replace github.com/testcontainers/testcontainers-go => ./extra-deps/testcontainers-go

require (
	github.com/gorilla/context v0.0.0-20160226214623-1ea25387ff6f
	github.com/gorilla/handlers v1.3.0
	github.com/gorilla/mux v1.7.3
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.8.0
	gopkg.in/mgo.v2 v2.0.0-20160818020120-3f83fa500528
)
