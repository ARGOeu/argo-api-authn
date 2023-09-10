package metrics

import (
	"context"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
)

func TrackMissingCertificateIpSan(ctx context.Context, binding bindings.Binding, store stores.Store) error {
	// check if there is an entry already
	metrics, err := store.QueryBindingMissingIpSanRecord(ctx, binding.UUID)
	if err != nil {
		return err
	}
	if len(metrics) > 0 {
		return nil
	}

	return store.InsertBindingMissingIpSanRecord(ctx, binding.UUID, binding.AuthIdentifier, utils.ZuluTimeNow())
}
