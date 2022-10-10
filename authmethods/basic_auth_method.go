package authmethods

import (
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
)

type BasicAuthMethod struct {
	ServiceUUID string `json:"service_uuid" required:"true"`
	Port        int    `json:"port" required:"true"`
	Host        string `json:"host" required:"true"`
	Type        string `json:"type" required:"true"`
	UUID        string `json:"uuid"`
	CreatedOn   string `json:"created_on"`
	UpdatedOn   string `json:"updated_on,omitempty"`
}

// TempBasicAuthMethod represents the fields that are allowed to be modified
type TempBasicAuthMethod struct {
	ServiceUUID string `json:"service_uuid" required:"true"`
	Port        int    `json:"port" required:"true"`
	Host        string `json:"host" required:"true"`
}

func (m *BasicAuthMethod) Validate(store stores.Store) error {

	var ok bool
	var err error
	var serviceType servicetypes.ServiceType

	// check if all required field have been provided
	if err = utils.ValidateRequired(*m); err != nil {
		err := utils.APIErrEmptyRequiredField("auth method", err.Error())
		return err
	}

	// check if the specified service type exists
	if serviceType, err = servicetypes.FindServiceTypeByUUID(m.ServiceUUID, store); err != nil {
		return err
	}

	// check if the given host belongs to the given service type
	if ok = serviceType.HasHost(m.Host); !ok {
		err = utils.APIErrNotFound("Host")
		return err
	}

	return err
}
