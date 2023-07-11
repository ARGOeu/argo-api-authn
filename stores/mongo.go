package stores

import (
	"context"

	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoStore struct {
	Server   string
	Database string
	Session  *mgo.Session
}

// SetUp initializes the mongo stores struct
func (mongo *MongoStore) SetUp() {

	for {
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   mongo.Server,
			},
		).Info("Trying to connect to Mongo")
		session, err := mgo.Dial(mongo.Server)
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   mongo.Server,
				},
			).Error(err.Error())
			continue
		}

		mongo.Session = session
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   mongo.Server,
			},
		).Info("Connection to Mongo established successfully")
		break
	}
}

func (mongo *MongoStore) Clone() Store {

	return &MongoStore{
		Server:   mongo.Server,
		Database: mongo.Database,
		Session:  mongo.Session.Clone(),
	}
}

func (mongo *MongoStore) Close() {
	mongo.Session.Close()
}

func (mongo *MongoStore) logError(ctx context.Context, funcName string, err error) {
	log.WithFields(
		log.Fields{
			"trace_id":        ctx.Value("trace_id"),
			"type":            "backend_log",
			"function":        funcName,
			"backend_service": "mongo",
			"backend_hosts":   mongo.Server,
		},
	).Error(err.Error())
}

func (mongo *MongoStore) QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")
	query := bson.M{}

	if name != "" {
		query = bson.M{"name": name}
	}

	err = c.Find(query).All(&qServices)

	if err != nil {
		mongo.logError(ctx, "QueryServiceTypes", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

func (mongo *MongoStore) QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")

	err = c.Find(bson.M{"uuid": uuid}).All(&qServices)

	if err != nil {
		mongo.logError(ctx, "QueryServiceTypesByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

func (mongo *MongoStore) QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error) {

	var err error
	var qAuthms []QApiKeyAuthMethod

	var query = bson.M{"service_uuid": serviceUUID, "host": host, "type": "api-key"}

	// if there is no serviceUUID and host provided, return all api key auth methods
	if serviceUUID == "" && host == "" {
		query = bson.M{"type": "api-key"}
	}

	c := mongo.Session.DB(mongo.Database).C("auth_methods")
	err = c.Find(query).All(&qAuthms)

	if err != nil {
		mongo.logError(ctx, "QueryApiKeyAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAuthms, err
	}

	return qAuthms, err
}

func (mongo *MongoStore) QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error) {

	var err error
	var qAuthms []QHeadersAuthMethod

	var query = bson.M{"service_uuid": serviceUUID, "host": host, "type": "headers"}

	// if there is no serviceUUID and host provided, return all api key auth methods
	if serviceUUID == "" && host == "" {
		query = bson.M{"type": "headers"}
	}

	c := mongo.Session.DB(mongo.Database).C("auth_methods")
	err = c.Find(query).All(&qAuthms)

	if err != nil {
		mongo.logError(ctx, "QueryHeadersAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAuthms, err
	}

	return qAuthms, err
}

func (mongo *MongoStore) InsertAuthMethod(ctx context.Context, am QAuthMethod) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Insert(am); err != nil {
		mongo.logError(ctx, "InsertAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

func (mongo *MongoStore) QueryBindingsByAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	c := mongo.Session.DB(mongo.Database).C("bindings")

	query := bson.M{
		"auth_identifier": authID,
		"service_uuid":    serviceUUID,
		"host":            host,
		"auth_type":       authType,
	}

	err = c.Find(query).All(&qBindings)

	if err != nil {
		mongo.logError(ctx, "QueryBindingsByAuthID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	q := bson.M{}

	if uuid != "" {
		q["uuid"] = uuid
	}

	if name != "" {
		q["name"] = name
	}

	c := mongo.Session.DB(mongo.Database).C("bindings")
	err = c.Find(q).All(&qBindings)

	if err != nil {
		mongo.logError(ctx, "QueryBindingsByUUIDAndName", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error
	query := bson.M{}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if serviceUUID != "" && host != "" {
		query = bson.M{"service_uuid": serviceUUID, "host": host}
	}

	if err = c.Find(query).All(&qBindings); err != nil {
		mongo.logError(ctx, "QueryBindings", err)
		err = utils.APIErrDatabase(err.Error())
		return qBindings, err
	}
	return qBindings, err
}

// InsertServiceType inserts a new service into the datastore
func (mongo *MongoStore) InsertServiceType(ctx context.Context, name string, hosts []string, authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	var qService QServiceType
	var err error

	qService = QServiceType{Name: name, Hosts: hosts, AuthTypes: authTypes, AuthMethod: authMethod, UUID: uuid, CreatedOn: createdOn, Type: sType}
	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Insert(qService); err != nil {
		mongo.logError(ctx, "InsertServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, nil
	}

	return qService, err
}

// InsertBinding inserts a new binding into the datastore
func (mongo *MongoStore) InsertBinding(ctx context.Context, name string, serviceUUID string, host string, uuid string, authID string, uniqueKey string, authType string) (QBinding, error) {

	var qBinding QBinding
	var err error

	qBinding = QBinding{
		Name:           name,
		ServiceUUID:    serviceUUID,
		Host:           host,
		UUID:           uuid,
		AuthIdentifier: authID,
		UniqueKey:      uniqueKey,
		AuthType:       authType,
		CreatedOn:      utils.ZuluTimeNow(),
	}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Insert(qBinding); err != nil {
		mongo.logError(ctx, "InsertBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, nil
	}

	return qBinding, err
}

// UpdateBinding updates the given binding
func (mongo *MongoStore) UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return updated, err
}

// UpdateServiceType updates the given binding
func (mongo *MongoStore) UpdateServiceType(ctx context.Context, original QServiceType, updated QServiceType) (QServiceType, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return updated, err
}

// UpdateAuthMethod updates the given auth method
func (mongo *MongoStore) UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")
	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return nil, err
	}

	return updated, err
}

func (mongo *MongoStore) DeleteServiceTypeByUUID(ctx context.Context, uuid string) error {

	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")

	err = c.Remove(bson.M{"uuid": uuid})

	if err != nil {
		mongo.logError(ctx, "DeleteServiceTypeByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

// DeleteBinding deletes a binding from the store
func (mongo *MongoStore) DeleteBinding(ctx context.Context, qBinding QBinding) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Remove(qBinding); err != nil {
		mongo.logError(ctx, "DeleteBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

func (mongo *MongoStore) DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if _, err = c.RemoveAll(bson.M{"service_uuid": serviceUUID}); err != nil {
		mongo.logError(ctx, "DeleteBindingByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return err
}

func (mongo *MongoStore) DeleteAuthMethod(ctx context.Context, am QAuthMethod) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Remove(am); err != nil {
		mongo.logError(ctx, "DeleteAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return err
}

func (mongo *MongoStore) DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if _, err = c.RemoveAll(bson.M{"service_uuid": serviceUUID}); err != nil {
		mongo.logError(ctx, "DeleteAuthMethodByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err

}
