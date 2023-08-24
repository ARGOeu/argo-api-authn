// +build integration

package stores

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"testing"
)

// mongodbContainer represents the mongodb container type used in the module
type mongodbContainer struct {
	testcontainers.Container
}

// startContainer creates an instance of the mongodb container type
func startContainer(ctx context.Context) (*mongodbContainer, error) {

	req := testcontainers.ContainerRequest{
		Name:         "mongodb-4.2-authn",
		Image:        "mongo:4.2",
		ExposedPorts: []string{"27017/tcp"},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &mongodbContainer{Container: container}, nil
}

type MongoStoreIntegrationTestSuite struct {
	suite.Suite
	store        Store
	ctx          context.Context
	ss           int
	serviceTypes []QServiceType
	apiKeyAms    []QApiKeyAuthMethod
	headersAms   []QHeadersAuthMethod
	bindings     []QBinding
}

func (suite *MongoStoreIntegrationTestSuite) initDB() {
	// Populate services
	service1 := QServiceType{
		Name:       "s1",
		Hosts:      []string{"host1", "host2", "host3"},
		AuthTypes:  []string{"x509", "oidc"},
		AuthMethod: "api-key",
		UUID:       "uuid1",
		CreatedOn:  "2018-05-05T18:04:05Z",
		Type:       "ams",
	}
	service2 := QServiceType{
		Name:       "s2",
		Hosts:      []string{"host3", "host4"},
		AuthTypes:  []string{"x509"},
		AuthMethod: "headers",
		UUID:       "uuid2",
		CreatedOn:  "2018-05-05T18:04:05Z",
		Type:       "web-api",
	}

	serviceTypes := []QServiceType{service1, service2}
	suite.serviceTypes = serviceTypes
	for _, serviceType := range serviceTypes {
		_, err := suite.store.InsertServiceType(suite.ctx, serviceType.Name, serviceType.Hosts, serviceType.AuthTypes,
			serviceType.AuthMethod, serviceType.UUID, serviceType.CreatedOn, serviceType.Type)
		if err != nil {
			log.Fatalf("Could not insert service type: %s, %s", serviceType.UUID, err.Error())
		}
	}

	// Populate Bindings
	binding1 := QBinding{
		Name:           "b1",
		ServiceUUID:    "uuid1",
		Host:           "host1",
		UUID:           "b_uuid1",
		AuthIdentifier: "test_dn_1",
		UniqueKey:      "unique_key_1",
		AuthType:       "x509",
		CreatedOn:      "2018-05-05T15:04:05Z",
		LastAuth:       "",
	}
	binding2 := QBinding{
		Name:           "b2",
		ServiceUUID:    "uuid1",
		Host:           "host1",
		UUID:           "b_uuid2",
		AuthIdentifier: "test_dn_2",
		UniqueKey:      "unique_key_2",
		AuthType:       "x509",
		CreatedOn:      "2018-05-05T15:04:05Z",
		LastAuth:       "",
	}
	binding3 := QBinding{
		Name:           "b3",
		ServiceUUID:    "uuid1",
		Host:           "host2",
		UUID:           "b_uuid3",
		AuthIdentifier: "test_dn_3",
		UniqueKey:      "unique_key_3",
		AuthType:       "x509",
		CreatedOn:      "2018-05-05T15:04:05Z",
		LastAuth:       "",
	}
	binding4 := QBinding{
		Name:           "b4",
		ServiceUUID:    "uuid2",
		Host:           "host3",
		UUID:           "b_uuid4",
		AuthIdentifier: "test_dn_1",
		UniqueKey:      "unique_key_1",
		AuthType:       "x509",
		CreatedOn:      "2018-05-05T15:04:05Z",
		LastAuth:       "",
	}

	bindings := []QBinding{binding1, binding2, binding3, binding4}
	suite.bindings = bindings
	for _, binding := range bindings {
		_, err := suite.store.InsertBinding(suite.ctx, binding.Name, binding.ServiceUUID, binding.Host,
			binding.UUID, binding.AuthIdentifier, binding.UniqueKey, binding.AuthType, binding.CreatedOn)
		if err != nil {
			log.Fatalf("Could not insert binding: %s, %s", binding.UUID, err.Error())
		}
	}

	// Populate AuthMethods
	amb1 := QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am1 := &QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1

	amb2 := QBasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	am2 := &QHeadersAuthMethod{Headers: map[string]string{"x-api-key": "key-1", "Accept": "application/json"}}
	am2.QBasicAuthMethod = amb2

	authMethods := []QAuthMethod{am1, am2}
	suite.apiKeyAms = []QApiKeyAuthMethod{*am1}
	suite.headersAms = []QHeadersAuthMethod{*am2}
	for _, method := range authMethods {
		err := suite.store.InsertAuthMethod(suite.ctx, method)
		if err != nil {
			log.Fatalf("Could not auth method: %+v, %s", method, err.Error())
		}
	}

}

func (suite *MongoStoreIntegrationTestSuite) SetupSuite() {
	suite.ss = 4
	suite.store.SetUp()
	suite.initDB()
}

func (suite *MongoStoreIntegrationTestSuite) TearDownSuite() {
	suite.ss = 4
	suite.store.Close()
}

func (suite *MongoStoreIntegrationTestSuite) TestQueryServiceTypes() {
	qs, _ := suite.store.QueryServiceTypes(suite.ctx, "")
	suite.Equal(2, len(qs))
	suite.Equal(suite.serviceTypes[0], qs[0])
	suite.Equal(suite.serviceTypes[1], qs[1])

	// test find by name
	qsByName, _ := suite.store.QueryServiceTypes(suite.ctx, "s1")
	suite.Equal(1, len(qsByName))
	suite.Equal(suite.serviceTypes[0], qs[0])

}

func (suite *MongoStoreIntegrationTestSuite) TestQueryServiceTypesByUUID() {
	qsByUUID, _ := suite.store.QueryServiceTypesByUUID(suite.ctx, "uuid1")
	suite.Equal(1, len(qsByUUID))
	suite.Equal(suite.serviceTypes[0], qsByUUID[0])

}

func (suite *MongoStoreIntegrationTestSuite) TestQueryApiKeyAuthMethods() {
	qsAM, _ := suite.store.QueryApiKeyAuthMethods(suite.ctx, "", "")
	suite.Equal(1, len(qsAM))
	suite.Equal(suite.apiKeyAms[0], qsAM[0])

	// by service uuid and host
	qsAM2, _ := suite.store.QueryApiKeyAuthMethods(suite.ctx, "uuid1", "host1")
	suite.Equal(1, len(qsAM2))
	suite.Equal(suite.apiKeyAms[0], qsAM2[0])
}

func (suite *MongoStoreIntegrationTestSuite) TestQueryHeadersAuthMethods() {
	qsAM, _ := suite.store.QueryHeadersAuthMethods(suite.ctx, "", "")
	suite.Equal(1, len(qsAM))
	suite.Equal(suite.headersAms[0], qsAM[0])

	// by service uuid and host
	qsAM2, _ := suite.store.QueryHeadersAuthMethods(suite.ctx, "uuid2", "host3")
	suite.Equal(1, len(qsAM2))
	suite.Equal(suite.headersAms[0], qsAM2[0])
}

func (suite *MongoStoreIntegrationTestSuite) TestQueryBindingsByAuthID() {
	qsB, _ := suite.store.QueryBindingsByAuthID(suite.ctx, "test_dn_1", "uuid1", "host1", "x509")
	suite.Equal(1, len(qsB))
	suite.Equal(suite.bindings[0].UUID, qsB[0].UUID)
	suite.Equal(suite.bindings[0].AuthIdentifier, qsB[0].AuthIdentifier)
	suite.Equal(suite.bindings[0].AuthType, qsB[0].AuthType)
	suite.Equal(suite.bindings[0].Name, qsB[0].Name)
	suite.Equal(suite.bindings[0].ServiceUUID, qsB[0].ServiceUUID)
	suite.Equal(suite.bindings[0].UniqueKey, qsB[0].UniqueKey)
}

func (suite *MongoStoreIntegrationTestSuite) TestQueryBindingsByUUIDAndName() {
	qsB, _ := suite.store.QueryBindingsByUUIDAndName(suite.ctx, "b_uuid1", "b1")
	suite.Equal(1, len(qsB))
	suite.Equal(suite.bindings[0].UUID, qsB[0].UUID)
	suite.Equal(suite.bindings[0].AuthIdentifier, qsB[0].AuthIdentifier)
	suite.Equal(suite.bindings[0].AuthType, qsB[0].AuthType)
	suite.Equal(suite.bindings[0].Name, qsB[0].Name)
	suite.Equal(suite.bindings[0].ServiceUUID, qsB[0].ServiceUUID)
	suite.Equal(suite.bindings[0].UniqueKey, qsB[0].UniqueKey)
}

func (suite *MongoStoreIntegrationTestSuite) TestQueryBindings() {
	qsB, _ := suite.store.QueryBindings(suite.ctx, "", "")
	suite.Equal(4, len(qsB))
	for idx, _ := range suite.bindings {
		suite.Equal(suite.bindings[idx].UUID, qsB[idx].UUID)
		suite.Equal(suite.bindings[idx].AuthIdentifier, qsB[idx].AuthIdentifier)
		suite.Equal(suite.bindings[idx].AuthType, qsB[idx].AuthType)
		suite.Equal(suite.bindings[idx].Name, qsB[idx].Name)
		suite.Equal(suite.bindings[idx].ServiceUUID, qsB[idx].ServiceUUID)
		suite.Equal(suite.bindings[idx].UniqueKey, qsB[idx].UniqueKey)
	}

	// by service uuid and host
	qsB2, _ := suite.store.QueryBindings(suite.ctx, "uuid1", "host1")
	suite.Equal(2, len(qsB2))
	for idx, _ := range qsB2 {
		suite.Equal(suite.bindings[idx].UUID, qsB2[idx].UUID)
		suite.Equal(suite.bindings[idx].AuthIdentifier, qsB2[idx].AuthIdentifier)
		suite.Equal(suite.bindings[idx].AuthType, qsB2[idx].AuthType)
		suite.Equal(suite.bindings[idx].Name, qsB2[idx].Name)
		suite.Equal(suite.bindings[idx].ServiceUUID, qsB2[idx].ServiceUUID)
		suite.Equal(suite.bindings[idx].UniqueKey, qsB2[idx].UniqueKey)
	}
}

func (suite *MongoStoreIntegrationTestSuite) TestCRUDServiceType() {

	// create
	insertedSt := QServiceType{
		Name:       "in_st",
		Hosts:      []string{"h1", "h2"},
		AuthTypes:  []string{"x509"},
		AuthMethod: "api-key",
		UUID:       "in_uuid",
		CreatedOn:  "now",
		Type:       "ams",
	}
	_, _ = suite.store.InsertServiceType(suite.ctx, insertedSt.Name, insertedSt.Hosts, insertedSt.AuthTypes,
		insertedSt.AuthMethod, insertedSt.UUID, insertedSt.CreatedOn, insertedSt.Type)
	i1, _ := suite.store.QueryServiceTypesByUUID(suite.ctx, "in_uuid")
	suite.Equal(insertedSt, i1[0])

	// update
	updatedSt := QServiceType{
		Name:       "u_st",
		Hosts:      []string{"uh1", "uh2"},
		AuthTypes:  []string{"x509"},
		AuthMethod: "api-key",
		UUID:       "in_uuid",
		CreatedOn:  "now",
		Type:       "ams",
	}
	_, _ = suite.store.UpdateServiceType(suite.ctx, insertedSt, updatedSt)
	i1u, _ := suite.store.QueryServiceTypesByUUID(suite.ctx, "in_uuid")
	suite.Equal(updatedSt, i1u[0])

	// delete
	e1 := suite.store.DeleteServiceTypeByUUID(suite.ctx, "in_uuid")
	suite.Nil(e1)
}

func (suite *MongoStoreIntegrationTestSuite) TestCRUDAuthMethod() {

	// create
	insertedAM := QApiKeyAuthMethod{
		QBasicAuthMethod: QBasicAuthMethod{
			ServiceUUID: "s_uuid1",
			Port:        9000,
			Host:        "h1",
			Type:        "api-key",
			UUID:        "u1",
			CreatedOn:   "now",
			UpdatedOn:   "now",
		},
		AccessKey: "a-k-1",
	}
	_ = suite.store.InsertAuthMethod(suite.ctx, insertedAM)
	qsAM2, _ := suite.store.QueryApiKeyAuthMethods(suite.ctx, "s_uuid1", "h1")
	suite.Equal(1, len(qsAM2))
	suite.Equal(insertedAM, qsAM2[0])

	// update
	updatedAM := QApiKeyAuthMethod{
		QBasicAuthMethod: QBasicAuthMethod{
			ServiceUUID: "s_uuid1",
			Port:        9999,
			Host:        "h1-u",
			Type:        "api-key",
			UUID:        "u1",
			CreatedOn:   "now",
			UpdatedOn:   "now",
		},
		AccessKey: "a-k-1",
	}
	_, _ = suite.store.UpdateAuthMethod(suite.ctx, insertedAM, updatedAM)
	qsAM2u, _ := suite.store.QueryApiKeyAuthMethods(suite.ctx, "s_uuid1", "h1-u")
	suite.Equal(1, len(qsAM2u))
	suite.Equal(updatedAM, qsAM2u[0])

	// delete
	e1 := suite.store.DeleteAuthMethod(suite.ctx, updatedAM)
	suite.Nil(e1)

	// create
	insertedAM2 := QHeadersAuthMethod{
		QBasicAuthMethod: QBasicAuthMethod{
			ServiceUUID: "s_uuid2",
			Port:        9000,
			Host:        "h1",
			Type:        "headers",
			UUID:        "u1",
			CreatedOn:   "now",
			UpdatedOn:   "now",
		},
		Headers: map[string]string{
			"h1": "v1",
		},
	}
	_ = suite.store.InsertAuthMethod(suite.ctx, insertedAM2)
	qsAM3, _ := suite.store.QueryHeadersAuthMethods(suite.ctx, "s_uuid2", "h1")
	suite.Equal(1, len(qsAM3))
	suite.Equal(insertedAM2, qsAM3[0])

	// update
	updatedAM2 := QHeadersAuthMethod{
		QBasicAuthMethod: QBasicAuthMethod{
			ServiceUUID: "s_uuid2",
			Port:        8080,
			Host:        "h2-u",
			Type:        "headers",
			UUID:        "u1",
			CreatedOn:   "now",
			UpdatedOn:   "now",
		},
		Headers: map[string]string{
			"h1-u": "v1-u",
		},
	}
	_, _ = suite.store.UpdateAuthMethod(suite.ctx, insertedAM2, updatedAM2)
	qsAM3u, _ := suite.store.QueryHeadersAuthMethods(suite.ctx, "s_uuid2", "h2-u")
	suite.Equal(1, len(qsAM3u))
	suite.Equal(updatedAM2, qsAM3u[0])

	// delete
	e2 := suite.store.DeleteAuthMethodByServiceUUID(suite.ctx, "s_uuid2")
	suite.Nil(e2)

}

func (suite *MongoStoreIntegrationTestSuite) TestCRUDBinding() {

	// create
	insertedBinding := QBinding{
		Name:           "in-b1",
		ServiceUUID:    "in-uuid1",
		Host:           "in-h1",
		AuthIdentifier: "auth-id-in",
		UUID:           "in-u",
		AuthType:       "x509",
		UniqueKey:      "uk1",
		CreatedOn:      "now",
	}

	_, _ = suite.store.InsertBinding(suite.ctx, insertedBinding.Name, insertedBinding.ServiceUUID,
		insertedBinding.Host, insertedBinding.UUID, insertedBinding.AuthIdentifier, insertedBinding.UniqueKey,
		insertedBinding.AuthType, insertedBinding.CreatedOn)
	qsB, _ := suite.store.QueryBindingsByAuthID(suite.ctx, "auth-id-in", "in-uuid1", "in-h1", "x509")
	suite.Equal(1, len(qsB))
	suite.Equal(insertedBinding.UUID, qsB[0].UUID)
	suite.Equal(insertedBinding.AuthIdentifier, qsB[0].AuthIdentifier)
	suite.Equal(insertedBinding.AuthType, qsB[0].AuthType)
	suite.Equal(insertedBinding.Name, qsB[0].Name)
	suite.Equal(insertedBinding.ServiceUUID, qsB[0].ServiceUUID)
	suite.Equal(insertedBinding.UniqueKey, qsB[0].UniqueKey)

	// update
	updatedBinding := QBinding{
		Name:           "in-b1",
		ServiceUUID:    "in-uuid1",
		Host:           "u-h1",
		AuthIdentifier: "auth-id-u",
		UUID:           "in-u",
		AuthType:       "x509",
		UniqueKey:      "uk1",
		CreatedOn:      "now",
	}
	_, _ = suite.store.UpdateBinding(suite.ctx, insertedBinding, updatedBinding)
	qsB2, _ := suite.store.QueryBindingsByAuthID(suite.ctx, "auth-id-u", "in-uuid1", "u-h1", "x509")
	suite.Equal(1, len(qsB2))
	suite.Equal(updatedBinding.UUID, qsB2[0].UUID)
	suite.Equal(updatedBinding.AuthIdentifier, qsB2[0].AuthIdentifier)
	suite.Equal(updatedBinding.AuthType, qsB2[0].AuthType)
	suite.Equal(updatedBinding.Name, qsB2[0].Name)
	suite.Equal(updatedBinding.ServiceUUID, qsB2[0].ServiceUUID)
	suite.Equal(updatedBinding.UniqueKey, qsB2[0].UniqueKey)

	// delete
	e1 := suite.store.DeleteBinding(suite.ctx, qsB2[0])
	suite.Nil(e1)

	// re insert to delete with uuid
	_, _ = suite.store.InsertBinding(suite.ctx, insertedBinding.Name, insertedBinding.ServiceUUID,
		insertedBinding.Host, insertedBinding.UUID, insertedBinding.AuthIdentifier, insertedBinding.UniqueKey,
		insertedBinding.AuthType, insertedBinding.CreatedOn)
	e2 := suite.store.DeleteBindingByServiceUUID(suite.ctx, "in-uuid1")
	suite.Nil(e2)
}

func TestMongoStoreIntegrationTestSuite(t *testing.T) {

	container, err := startContainer(context.Background())
	if err != nil {
		panic("Could not start container for mongodb integration tests. " + err.Error())
	}

	p, _ := container.MappedPort(context.Background(), "27017/tcp")

	mongoDBUri := fmt.Sprintf("mongodb://localhost:%s", p.Port())

	mongoStore := &MongoStore{
		Server:   mongoDBUri,
		Database: "argo_ams",
	}
	suite.Run(t, &MongoStoreIntegrationTestSuite{
		store: mongoStore,
		ctx:   context.Background(),
	})
}
