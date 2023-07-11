package authmethods

import (
	"context"
	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
)

type AuthMethodFactory struct{}

func NewAuthMethodFactory() *AuthMethodFactory {
	return &AuthMethodFactory{}
}

func (f *AuthMethodFactory) Create(ctx context.Context, amType string) (AuthMethod, error) {

	var err error
	var ok bool
	var am AuthMethod
	var aMInit AuthMethodInit

	if aMInit, ok = AuthMethodsTypes[amType]; !ok {
		err = utils.APIGenericInternalError("Type is supported but not found")
		log.WithFields(
			log.Fields{
				"trace_id": ctx.Value("trace_id"),
				"type":     "service_log",
			},
		).Errorf("Type: %v was requested, but was not found inside the source code despite being supported", amType)
		return am, err
	}

	return aMInit(), err
}
