package stores

import (
	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
)

type QServiceType struct {
	Name       string   `json:"name" bson:"name"`
	Hosts      []string `json:"hosts" bson:"hosts"`
	AuthTypes  []string `json:"auth_types" bson:"auth_types"`
	AuthMethod string   `json:"auth_method" bson:"auth_method"`
	UUID       string   `json:"uuid" bson:"uuid"`
	CreatedOn  string   `json:"created_on,omitempty" bson:"created_on,omitempty"`
	UpdatedOn  string   `json:"updated_on,omitempty" bson:"updated_on,omitempty"`
	Type       string   `json:"type" bson:"type"`
}

type QBinding struct {
	Name           string `json:"name" bson:"name"`
	ServiceUUID    string `json:"service_uuid" bson:"service_uuid"`
	Host           string `json:"host" bson:"host"`
	AuthIdentifier string `json:"auth_identifier" bson:"auth_identifier"`
	UUID           string `json:"uuid" bson:"uuid"`
	AuthType       string `json:"auth_type" bson:"auth_type"`
	UniqueKey      string `json:"unique_key,omitempty"`
	CreatedOn      string `json:"created_on,omitempty" bson:"created_on,omitempty"`
	UpdatedOn      string `json:"updated_on,omitempty" bson:"updated_on,omitempty"`
	LastAuth       string `json:"last_auth,omitempty" bson:"last_auth,omitempty"`
}

type QAuthMethod interface {
	Uuid() string
}

type QBasicAuthMethod struct {
	ServiceUUID string `json:"service_uuid" bson:"service_uuid"`
	Port        int    `json:"port" bson:"port"`
	Host        string `json:"host" bson:"host"`
	Type        string `json:"type" bson:"type"`
	UUID        string `json:"uuid" bson:"uuid"`
	CreatedOn   string `json:"created_on" bson:"created_on"`
	UpdatedOn   string `json:"updated_on,omitempty" bson:"updated_on,omitempty"`
}

func (q QBasicAuthMethod) Uuid() string {
	return q.UUID
}

type QApiKeyAuthMethod struct {
	QBasicAuthMethod `bson:",inline"`
	AccessKey        string `json:"access_key" bson:"access_key"`
}

type QHeadersAuthMethod struct {
	QBasicAuthMethod `bson:",inline"`
	Headers          map[string]string `json:"headers" bson:"headers"`
}

type QAuthMethodFactory struct{}

func (f *QAuthMethodFactory) Create(amType string) (QAuthMethod, error) {

	var err error
	var ok bool
	var am QAuthMethod
	var qAmInit QAuthMethodInit

	if qAmInit, ok = QAuthMethodsTypes[amType]; !ok {
		err = utils.APIGenericInternalError("Type is supported but not found")
		log.WithFields(
			log.Fields{
				"type": "service_log",
			},
		).Errorf("Type: %v was requested,"+
			" but was not found inside the source code(store) despite being supported", amType)
		return am, err
	}

	return qAmInit(), err
}

type QAuthMethodInit func() QAuthMethod

var QAuthMethodsTypes = map[string]QAuthMethodInit{
	"api-key": NewQApiKeyAuthMethod,
	"headers": NewQHeadersAuthMethod,
}

func NewQApiKeyAuthMethod() QAuthMethod {
	return new(QApiKeyAuthMethod)
}

func NewQHeadersAuthMethod() QAuthMethod {
	return new(QHeadersAuthMethod)
}
