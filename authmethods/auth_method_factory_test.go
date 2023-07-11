package authmethods

import (
	"context"
	"github.com/stretchr/testify/suite"
	"testing"
)

type AuthMethodFactoryTestSuite struct {
	suite.Suite
}

func (suite *AuthMethodFactoryTestSuite) TestCreate() {

	ctx := context.Background()

	// tests the normal case
	am, err1 := NewAuthMethodFactory().Create(ctx, "api-key")

	// mismatch
	_, err2 := NewAuthMethodFactory().Create(ctx, "mis_type")

	suite.Equal(&ApiKeyAuthMethod{}, am)

	suite.Nil(err1)
	suite.Equal("Internal Error: Type is supported but not found", err2.Error())

}

func TestAuthMethodFactorySuite(t *testing.T) {
	suite.Run(t, new(AuthMethodFactoryTestSuite))
}
