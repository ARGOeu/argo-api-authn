package stores

type Store interface {
	SetUp()
	Close()
	QueryServiceTypes(name string) ([]QServiceType, error)
	QueryServiceTypesByUUID(uuid string) ([]QServiceType, error)
	DeprecatedQueryAuthMethods(serviceUUID string, host string, typeName string) ([]map[string]interface{}, error)
	QueryBindingsByDN(dn string, serviceUUID string, host string) ([]QBinding, error)
	QueryBindingsByUUID(uuid string) ([]QBinding, error)
	QueryBindings(serviceUUID string, host string) ([]QBinding, error)
	InsertServiceType(name string, hosts []string, authTypes []string, authMethod string, uuid string, retrievalField string, createdOn string, sType string) (QServiceType, error)
	DeprecatedInsertAuthMethod(authM map[string]interface{}) error
	InsertBinding(name string, serviceUUID string, host string, uuid string, dn string, oidcToken string, uniqueKey string) (QBinding, error)
	UpdateBinding(original QBinding, updated QBinding) (QBinding, error)
	UpdateServiceType(original QServiceType, updated QServiceType) (QServiceType, error)
	DeleteBinding(qBinding QBinding) error
	DeprecatedDeleteAuthMethod(authM map[string]interface{}) error
}
