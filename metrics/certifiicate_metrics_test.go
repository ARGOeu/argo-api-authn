package metrics

import (
	"context"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/stretchr/testify/suite"
	"testing"
)

type CertificateMetricsTestSuite struct {
	suite.Suite
}

func (suite *CertificateMetricsTestSuite) TestTrackMissingCertificateIpSan() {

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// binding already has tracked record
	b := bindings.Binding{
		UUID: "b_uuid1",
	}

	suite.Equal(1, len(mockstore.MissingIpSanRecords))
	suite.Nil(TrackMissingCertificateIpSan(context.Background(), b, mockstore))

	b2 := bindings.Binding{
		UUID: "new_b_uuid1",
	}

	suite.Equal(1, len(mockstore.MissingIpSanRecords))
	suite.Nil(TrackMissingCertificateIpSan(context.Background(), b2, mockstore))
	suite.Equal(2, len(mockstore.MissingIpSanRecords))
}

func TestCertificateMetricsTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateMetricsTestSuite))
}
