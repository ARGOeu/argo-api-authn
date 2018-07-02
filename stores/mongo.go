package stores

import (
	"github.com/ARGOeu/argo-api-authn/utils"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	LOGGER  "github.com/sirupsen/logrus"
)

type MongoStore struct {
	Server   string
	Database string
	Session  *mgo.Session
}

// Initialize initializes the mongo stores struct
func (mongo *MongoStore) SetUp() {

	var err error
	var session = &mgo.Session{}

	session, err = mgo.Dial(mongo.Server)
	mongo.Session = session

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		return
	}

	LOGGER.Info("STORE", "\t", "Connected to Mongo: ", mongo.Server)

}

func (mongo *MongoStore) Close() {
	mongo.Session.Close()
}

func (mongo *MongoStore) QueryServiceTypes(name string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")
	query := bson.M{}

	if name != "" {
		query = bson.M{"name": name}
	}

	err = c.Find(query).All(&qServices)

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

func (mongo *MongoStore) QueryServiceTypesByUUID(uuid string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")

	err = c.Find(bson.M{"uuid": uuid}).All(&qServices)

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

// Deprecated: QueryAuthMethods
func (mongo *MongoStore) DeprecatedQueryAuthMethods(serviceUUID string, host string, typeName string) ([]map[string]interface{}, error) {

	var qAuthMethods = []map[string]interface{}{}
	var err error

	query := bson.M{}

	if serviceUUID != "" && host != "" && typeName != "" {
		query = bson.M{"type": typeName, "service_uuid": serviceUUID, "host": host}
	}

	c := mongo.Session.DB(mongo.Database).C("auth_methods")
	err = c.Find(query).All(&qAuthMethods)

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return qAuthMethods, err
	}

	LOGGER.Info(qAuthMethods)

	return qAuthMethods, err
}

func (mongo *MongoStore) QueryBindingsByDN(dn string, serviceUUID string, host string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	c := mongo.Session.DB(mongo.Database).C("bindings")
	err = c.Find(bson.M{"dn": dn, "service_uuid": serviceUUID, "host": host}).All(&qBindings)

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindingsByUUID(uuid string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	c := mongo.Session.DB(mongo.Database).C("bindings")
	err = c.Find(bson.M{"uuid": uuid}).All(&qBindings)

	if err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindings(serviceUUID string, host string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error
	query := bson.M{}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if serviceUUID != "" && host != "" {
		query = bson.M{"service_uuid": serviceUUID, "host": host}
	}

	if err = c.Find(query).All(&qBindings); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return qBindings, err
	}
	return qBindings, err
}

//InsertServiceType inserts a new service into the datastore
func (mongo *MongoStore) InsertServiceType(name string, hosts []string, authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	var qService QServiceType
	var err error

	qService = QServiceType{Name: name, Hosts: hosts, AuthTypes: authTypes, AuthMethod: authMethod, UUID: uuid, CreatedOn: createdOn, Type: sType}
	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Insert(qService); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, nil
	}

	return qService, err
}

// Deprecated: DeprecatedInsertAuthMethod inserts a new auth method to the database
func (mongo *MongoStore) DeprecatedInsertAuthMethod(authM map[string]interface{}) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Insert(authM); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

//InsertBinding inserts a new binding into the datastore
func (mongo *MongoStore) InsertBinding(name string, serviceUUID string, host string, uuid string, dn string, oidcToken string, uniqueKey string) (QBinding, error) {

	var qBinding QBinding
	var err error

	qBinding = QBinding{Name: name, ServiceUUID: serviceUUID, Host: host, UUID: uuid, DN: dn, OIDCToken: oidcToken, UniqueKey: uniqueKey, CreatedOn: utils.ZuluTimeNow()}
	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Insert(qBinding); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, nil
	}

	return qBinding, err
}

//UpdateBinding updates the given binding
func (mongo *MongoStore) UpdateBinding(original QBinding, updated QBinding) (QBinding, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Update(original, updated); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return updated, err
}

//UpdateServiceType updates the given binding
func (mongo *MongoStore) UpdateServiceType(original QServiceType, updated QServiceType) (QServiceType, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Update(original, updated); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return updated, err
}

// Delete binding deletes a binding from the store
func (mongo *MongoStore) DeleteBinding(qBinding QBinding) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Remove(qBinding); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

// Deprecated: DeprecatedDeleteAuthMethod deletes the given auth method from the store
func (mongo *MongoStore) DeprecatedDeleteAuthMethod(authM map[string]interface{}) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Remove(authM); err != nil {
		LOGGER.Error("STORE", "\t", err.Error())
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return err

}
