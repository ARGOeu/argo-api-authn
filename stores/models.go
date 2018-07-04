package stores

type QServiceType struct {
	Name       string   `json:"name" bson:"name"`
	Hosts      []string `json:"hosts" bson:"hosts"`
	AuthTypes  []string `json:"auth_types" bson:"auth_types"`
	AuthMethod string   `json:"auth_method" bson:"auth_method"`
	UUID       string   `json:"uuid" bson:"uuid"`
	CreatedOn  string   `json:"created_on,omitempty" bson:"created_on,omitempty"`
	Type       string   `json:"type" bson:"type"`
}

type QBinding struct {
	Name        string `json:"name" bson:"name"`
	ServiceUUID string `json:"service_uuid" bson:"service_uuid"`
	Host        string `json:"host" bson:"host"`
	DN          string `json:"dn,omitempty" bson:"dn,omitempty"`
	UUID        string `json:"uuid" bson:"uuid"`
	OIDCToken   string `json:"oidc_token,omitempty"`
	UniqueKey   string `json:"unique_key,omitempty"`
	CreatedOn   string `json:"created_on,omitempty" bson:"created_on,omitempty"`
	LastAuth    string `json:"last_auth,omitempty" bson:"last_auth,omitempty"`
}

type QApiKeyAuth struct {
	Type      string `json:"type" bson:"type"`
	Service   string `json:"service" bson:"service"`
	Host      string `json:"host" bson:"host"`
	Port      int    `json:"port" bson:"port"`
	Path      string `json:"path" bson:"path"`
	AccessKey string `json:"access_key" bson:"access_key"`
}

type QAuthMethod interface {}

type QBasicAuthMethod struct {
	ServiceUUID    string `json:"service_uuid" bson:"service_uuid"`
	Port           int    `json:"port" bson:"port"`
	Host           string `json:"host" bson:"host"`
	RetrievalField string `json:"retrieval_field" bson:"retrieval_field"`
	Path           string `json:"path" bson:"path"`
	UUID           string `json:"uuid" bson:"uuid"`
	CreatedOn      string `json:"created_on" bson:"created_on"`
}

type QApiKeyAuthMethod struct {
	QBasicAuthMethod `bson:",inline"`
	AccessKey string `json:"access_key" bson:"access_key"`
}