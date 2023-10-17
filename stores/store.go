package stores

import "context"

type Store interface {
	SetUp()
	Close()
	Clone() Store
	QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error)
	QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error)
	QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error)
	QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error)
	QueryBindingsByAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string) ([]QBinding, error)
	QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error)
	QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error)
	InsertServiceType(ctx context.Context, name string, hosts []string, authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error)
	DeleteServiceTypeByUUID(ctx context.Context, uuid string) error
	InsertAuthMethod(ctx context.Context, am QAuthMethod) error
	DeleteAuthMethod(ctx context.Context, am QAuthMethod) error
	DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error
	InsertBinding(ctx context.Context, name string, serviceUUID string, host string, uuid string, authID string, uniqueKey string, authType string) (QBinding, error)
	UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error)
	UpdateServiceType(ctx context.Context, original QServiceType, updated QServiceType) (QServiceType, error)
	UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error)
	DeleteBinding(ctx context.Context, qBinding QBinding) error
	DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error
	InsertBindingMissingIpSanRecord(ctx context.Context, bindingUUID, bindingAuthId, createdOn string) error
	QueryBindingMissingIpSanRecord(ctx context.Context, bindingUUID string) ([]QMissingIpSanMetric, error)
}
