package authmethods

import (
	"fmt"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/asaskevich/govalidator"
	"strconv"
)

type BasicAuthMethod struct {
	ServiceUUID    string `json:"service_uuid" required:"true"`
	Port           int    `json:"port" required:"true"`
	Host           string `json:"host" required:"true"`
	RetrievalField string `json:"retrieval_field" required:"true"`
	Path           string `json:"path" required:"true"`
	Type           string `json:"type" required:"true"`
	UUID           string `json:"uuid"`
	CreatedOn      string `json:"created_on"`
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

	// construct the full path and check if it resembles a proper url
	url := fmt.Sprintf("https://%v:%v%v", m.Host, strconv.Itoa(m.Port), m.Path)
	if ok = govalidator.IsURL(url); !ok {
		err = &utils.APIError{Code: 422, Message: "The url to access resources in invalid. URL: " + url, Status: "UNPROCESSABLE ENTITY"}
		return err
	}

	return err
}
