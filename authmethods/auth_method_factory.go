package authmethods

import (
	"github.com/ARGOeu/argo-api-authn/utils"
	LOGGER "github.com/sirupsen/logrus"
)

type AuthMethodFactory struct{}

func NewAuthMethodFactory() *AuthMethodFactory {
	return &AuthMethodFactory{}
}

func (f *AuthMethodFactory) Create(amType string) (AuthMethod, error) {

	var err error
	var ok bool
	var am AuthMethod
	var aMInit AuthMethodInit

	if amType == "api-key" {
		return new(ApiKeyAuthMethod), nil
	}

	if aMInit, ok = AuthMethodsTypes[amType]; !ok {
		err = utils.APIGenericInternalError("Type is supported but not found")
		LOGGER.Errorf("Type: %v was requested, but was not found inside the source code despite being supported", amType)
		return am, err
	}

	return aMInit(), err
}
