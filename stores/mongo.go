package stores

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
	officialBson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const (
	ServiceTypesCollection = "service_types"
	BindingsCollection     = "bindings"
	AuthMethodsCollection  = "auth_methods"
)

type MongoStoreWithOfficialDriver struct {
	Server   string
	Database string
	database *mongo.Database
	client   *mongo.Client
}

func (store *MongoStoreWithOfficialDriver) logError(ctx context.Context, funcName string, err error) {
	log.WithFields(
		log.Fields{
			"trace_id":        ctx.Value("trace_id"),
			"type":            "backend_log",
			"function":        funcName,
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Error(err.Error())
}

func (store *MongoStoreWithOfficialDriver) SetUp() {

	mongoDBUri := fmt.Sprintf("mongodb://%s", store.Server)

	for {
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   store.Server,
			},
		).Info("Trying to connect to Mongo")
		clientOptions := options.Client().ApplyURI(mongoDBUri)
		err := clientOptions.Validate()
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   store.Server,
				},
			).Error(err.Error())
			continue
		}
		client, err := mongo.Connect(options.Client().ApplyURI(mongoDBUri))
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   store.Server,
				},
			).Error(err.Error())
			continue
		}
		store.client = client
		break
	}

	log.WithFields(
		log.Fields{
			"type":            "backend_log",
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Info("Connection to Mongo established successfully")

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   store.Server,
			},
		).Info("Trying to ping to Mongo")
		err := store.client.Ping(ctx, readpref.Primary())
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   store.Server,
				},
			).Error(err.Error())
			continue
		}
		cancel()
		break
	}

	log.WithFields(
		log.Fields{
			"type":            "backend_log",
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Info("Mongo Deployment is up and running")
	store.database = store.client.Database(store.Database)
}

func (store *MongoStoreWithOfficialDriver) Close() {
	if store.client != nil {
		if err := store.client.Disconnect(context.Background()); err != nil {
			log.Fatalf("Could not disconnect mongo client, %s", err.Error())
		}
	}
}

func (store *MongoStoreWithOfficialDriver) Clone() Store {
	return store
}

func (store *MongoStoreWithOfficialDriver) InsertBindingMissingIpSanRecord(ctx context.Context, bindingUUID, bindingAuthId, createdOn string) error {

	qMetric := QMissingIpSanMetric{
		BindingUUID:           bindingUUID,
		BindingAuthIdentifier: bindingAuthId,
		CreatedOn:             createdOn,
	}

	_, err := store.database.Collection("bindings_missing_ip_san").InsertOne(ctx, qMetric)
	if err != nil {
		store.logError(ctx, "InsertBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindingMissingIpSanRecord(ctx context.Context,
	bindingUUID string) ([]QMissingIpSanMetric, error) {

	var qMetrics []QMissingIpSanMetric
	query := officialBson.M{}

	if bindingUUID != "" {
		query["binding_uuid"] = bindingUUID
	}
	cursor, err := store.database.Collection("bindings_missing_ip_san").Find(ctx, query)
	if err != nil {
		return qMetrics, err
	}

	for cursor.Next(ctx) {
		var result QMissingIpSanMetric
		err := cursor.Decode(&result)
		if err != nil {
			store.logError(ctx, "QueryBindingMissingIpSanRecord", err)
			err = utils.APIErrDatabase(err.Error())
			return qMetrics, err
		}
		qMetrics = append(qMetrics, result)
	}

	if err := cursor.Err(); err != nil {
		store.logError(ctx, "QueryBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return qMetrics, err
	}

	return qMetrics, nil
}

// ##### CRUD SERVICE TYPES #####

func executeRetrieveQuery[T any](ctx context.Context, query officialBson.M, col *mongo.Collection) ([]T, error) {
	var results []T
	cursor, err := col.Find(ctx, query)
	if err != nil {
		return results, err
	}
	err = cursor.All(ctx, &results)
	if err != nil {
		return results, err
	}
	return results, nil
}

func (store *MongoStoreWithOfficialDriver) QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error) {

	query := officialBson.M{}

	if name != "" {
		query["name"] = name
	}

	qServices, err := executeRetrieveQuery[QServiceType](ctx, query, store.database.Collection(ServiceTypesCollection))
	if err != nil {
		store.logError(ctx, "QueryServiceTypes", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, nil
}

func (store *MongoStoreWithOfficialDriver) QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error) {
	query := officialBson.M{"uuid": uuid}

	qServices, err := executeRetrieveQuery[QServiceType](ctx, query, store.database.Collection(ServiceTypesCollection))
	if err != nil {
		store.logError(ctx, "QueryServiceTypesByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, nil
}

func (store *MongoStoreWithOfficialDriver) InsertServiceType(ctx context.Context, name string, hosts []string,
	authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	qService := QServiceType{
		Name:       name,
		Hosts:      hosts,
		AuthTypes:  authTypes,
		AuthMethod: authMethod,
		UUID:       uuid,
		CreatedOn:  createdOn,
		Type:       sType,
	}

	_, err := store.database.Collection(ServiceTypesCollection).InsertOne(ctx, qService)
	if err != nil {
		store.logError(ctx, "InsertServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return qService, nil
}

func (store *MongoStoreWithOfficialDriver) DeleteServiceTypeByUUID(ctx context.Context, uuid string) error {
	query := officialBson.M{"uuid": uuid}
	_, err := store.database.Collection(ServiceTypesCollection).DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteServiceTypeByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) UpdateServiceType(ctx context.Context,
	original QServiceType, updated QServiceType) (QServiceType, error) {

	query := officialBson.D{{"uuid", original.UUID}}
	updateQuery := officialBson.D{
		{"$set", officialBson.D{
			{"name", updated.Name},
			{"hosts", updated.Hosts},
			{"auth_types", updated.AuthTypes},
			{"auth_method", updated.AuthMethod},
			{"created_on", updated.CreatedOn},
			{"updated_on", updated.UpdatedOn},
			{"type", updated.Type},
		}}}
	_, err := store.database.Collection(ServiceTypesCollection).UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}
	return updated, nil
}

//	###### CRUD AUTH METHODS ######

func (store *MongoStoreWithOfficialDriver) QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error) {

	c := store.database.Collection(AuthMethodsCollection)

	// if there is no serviceUUID and host provided, return all api key auth methods
	query := officialBson.M{"type": "api-key"}
	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}

	qAms, err := executeRetrieveQuery[QApiKeyAuthMethod](ctx, query, c)
	if err != nil {
		store.logError(ctx, "QueryApiKeyAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return []QApiKeyAuthMethod{}, err
	}

	return qAms, nil
}

func (store *MongoStoreWithOfficialDriver) QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error) {

	c := store.database.Collection(AuthMethodsCollection)

	// if there is no serviceUUID and host provided, return all api key auth methods
	query := officialBson.M{"type": "headers"}
	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}

	qAms, err := executeRetrieveQuery[QHeadersAuthMethod](ctx, query, c)
	if err != nil {
		store.logError(ctx, "QueryHeadersAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return []QHeadersAuthMethod{}, err
	}

	return qAms, nil
}

func (store *MongoStoreWithOfficialDriver) InsertAuthMethod(ctx context.Context, am QAuthMethod) error {
	_, err := store.database.Collection(AuthMethodsCollection).InsertOne(ctx, am)
	if err != nil {
		store.logError(ctx, "InsertAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return nil
}

func (store *MongoStoreWithOfficialDriver) UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error) {

	var query officialBson.D
	var updateQuery officialBson.D

	if apiKeyAM, ok := updated.(QApiKeyAuthMethod); ok {

		query = officialBson.D{{"uuid", apiKeyAM.UUID}}
		updateQuery = officialBson.D{{"$set", officialBson.D{
			{"access_key", apiKeyAM.AccessKey},
			{"service_uuid", apiKeyAM.ServiceUUID},
			{"host", apiKeyAM.Host},
			{"port", apiKeyAM.Port},
			{"created_on", apiKeyAM.CreatedOn},
			{"updated_on", apiKeyAM.UpdatedOn},
			{"type", apiKeyAM.Type},
		}}}
	} else if headersAm, ok := updated.(QHeadersAuthMethod); ok {
		query = officialBson.D{{"uuid", headersAm.UUID}}
		updateQuery = officialBson.D{{"$set", officialBson.D{
			{"headers", headersAm.Headers},
			{"service_uuid", headersAm.ServiceUUID},
			{"host", headersAm.Host},
			{"port", headersAm.Port},
			{"created_on", headersAm.CreatedOn},
			{"updated_on", headersAm.UpdatedOn},
			{"type", headersAm.Type},
		}}}
	} else {
		err := errors.New("unknown Auth method type")
		store.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return original, err
	}

	_, err := store.database.Collection(AuthMethodsCollection).UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return original, err
	}
	return updated, nil

}

func (store *MongoStoreWithOfficialDriver) DeleteAuthMethod(ctx context.Context, am QAuthMethod) error {
	query := officialBson.M{"uuid": am.Uuid()}
	_, err := store.database.Collection(AuthMethodsCollection).DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error {
	query := officialBson.M{"service_uuid": serviceUUID}
	_, err := store.database.Collection(AuthMethodsCollection).DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteAuthMethodByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

//	###### CRUD BINDINGS ######

func (store *MongoStoreWithOfficialDriver) QueryBindingsByAuthID(ctx context.Context, authID string,
	serviceUUID string, host string, authType string) ([]QBinding, error) {
	query := officialBson.M{
		"auth_identifier": authID,
		"service_uuid":    serviceUUID,
		"host":            host,
		"auth_type":       authType,
	}

	qBindings, err := executeRetrieveQuery[QBinding](ctx, query, store.database.Collection(BindingsCollection))

	if err != nil {
		store.logError(ctx, "QueryBindingsByAuthID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error) {
	query := officialBson.M{}

	if uuid != "" {
		query["uuid"] = uuid
	}

	if name != "" {
		query["name"] = name
	}

	qBindings, err := executeRetrieveQuery[QBinding](ctx, query, store.database.Collection(BindingsCollection))

	if err != nil {
		store.logError(ctx, "QueryBindingsByUUIDAndName", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error) {
	query := officialBson.M{}

	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}

	qBindings, err := executeRetrieveQuery[QBinding](ctx, query, store.database.Collection(BindingsCollection))

	if err != nil {
		store.logError(ctx, "QueryBindings", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) InsertBinding(ctx context.Context, name string, serviceUUID string,
	host string, uuid string, authID string, uniqueKey string, authType string, createdOn string) (QBinding, error) {

	qBinding := QBinding{
		Name:           name,
		ServiceUUID:    serviceUUID,
		Host:           host,
		UUID:           uuid,
		AuthIdentifier: authID,
		UniqueKey:      uniqueKey,
		AuthType:       authType,
		CreatedOn:      createdOn,
	}

	_, err := store.database.Collection("bindings").InsertOne(ctx, qBinding)
	if err != nil {
		store.logError(ctx, "InsertBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return qBinding, nil
}

func (store *MongoStoreWithOfficialDriver) UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error) {
	query := officialBson.D{{"uuid", original.UUID}}
	updateQuery := officialBson.D{
		{"$set", officialBson.D{
			{"name", updated.Name},
			{"service_uuid", updated.ServiceUUID},
			{"host", updated.Host},
			{"auth_identifier", updated.AuthIdentifier},
			{"auth_type", updated.AuthType},
			{"unique_key", updated.UniqueKey},
			{"created_on", updated.CreatedOn},
			{"updated_on", updated.UpdatedOn},
			{"last_auth", updated.LastAuth},
		}}}
	_, err := store.database.Collection("bindings").UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}
	return updated, nil
}

func (store *MongoStoreWithOfficialDriver) DeleteBinding(ctx context.Context, qBinding QBinding) error {
	query := officialBson.M{"uuid": qBinding.UUID}
	_, err := store.database.Collection("bindings").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error {
	query := officialBson.M{"service_uuid": serviceUUID}
	_, err := store.database.Collection("bindings").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteBindingByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}
