package kerberos

import (
	"encoding/json"
	"testing"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"encoding/hex"

	//"gopkg.in/jcmturner/gokrb5.v7/messages"
	testdata "gopkg.in/jcmturner/gokrb5.v7/test/testdata"
	"gopkg.in/jcmturner/gokrb5.v7/types"

	common "github.com/spiffe/spire/pkg/common/plugin/kerberos"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
)

type mockKerberos struct{mock.Mock}

func (m *mockKerberos) LoadKeyTab() {

}

func (m *mockKerberos) 	LoadConfig() {

}
func (m *mockKerberos) 	VerifyAPRequest(kt *gokrbkeytab.Keytab, attestedData *common.KrbAttestedData) (bool, *credentials.Credentials, error) {
	args := m.Called(kt, attestedData)
	return args.Bool(0), args.Get(1).(*credentials.Credentials), args.Error(2)
}



func Test_PluginAttest(t *testing.T) {
	t.Log("testing Attest - node attestor plugin for kerberos")

	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := gokrbkeytab.New()
	err := kt.Unmarshal(b)
	assert.Nil(t, err, "Unable to unmarshal test keytab data")

	mk := &mockKerberos{}
	p := &Plugin{Kerberos: mk, keytab: kt, trustDomain: "example.com"}

	t.Run("should attest node", func(t *testing.T) {
		
		attestedData := &common.KrbAttestedData{}
		payload, err := json.Marshal(attestedData)
		assert.Nil(t, err)
		req := &nodeattestorv1.AttestRequest {Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}
		c := &credentials.Credentials{}
		c = c.WithKeytab(kt)
		c.SetDomain("testing")
		c.SetDisplayName("node.testing.com")
		mk.On("VerifyAPRequest",kt, attestedData).Return(true, c , nil)
		c.SetCName(types.NewPrincipalName(0, "node.testing.com"))
		id, selectors, err := p.attestRequest(req)
		assert.Nil(t, err)
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, selectors)
	
		t.Logf("id - %s, selectors - %s", id, selectors)
	})

	t.Run("cannot parse attest data", func(t *testing.T) {
		req := &nodeattestorv1.AttestRequest {Request: &nodeattestorv1.AttestRequest_Payload{Payload: []byte("cannot parse this")}}
		id, selectors, err := p.attestRequest(req)
		assert.NotNil(t, err)
		assert.Empty(t, id)
		assert.Empty(t, selectors)
		
	})
	

}

