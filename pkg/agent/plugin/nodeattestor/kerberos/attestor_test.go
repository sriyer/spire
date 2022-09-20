package kerberos

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	gokrbcrypto "gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/iana/etypeID"
	gokrbmsgs "gopkg.in/jcmturner/gokrb5.v7/messages"
	gokrbtypes "gopkg.in/jcmturner/gokrb5.v7/types"
)

func TestPlugin_Attest(t *testing.T) {
	t.Run("should successfully attest", func(t *testing.T) {
		mk := &mockKerberos{}
		cname := gokrbtypes.PrincipalName{}
		realm := "testing"
		authenticator := gokrbtypes.Authenticator{}
		eType := gokrbcrypto.Aes128CtsHmacSha96{}
		encyrptionKey := gokrbtypes.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96}
		ticket := gokrbmsgs.Ticket{Realm: realm}
		apRequest := gokrbmsgs.APReq{
			Ticket: ticket,
		}
		mk.On("Login").Return(nil)
		mk.On("GetServiceTicket", "testing").Return(ticket, encyrptionKey, nil)
		mk.On("GetCredentialDomain").Return(realm)
		mk.On("GetCredentialCName").Return(cname)
		mk.On("GetAuthenitcator", "testing", cname).Return(authenticator, nil)
		mk.On("GetEncryptionType", etypeID.AES128_CTS_HMAC_SHA1_96).Return(eType, nil)
		mk.On("GetSequenceNumberAndSubKey", authenticator, eType).Return(nil)
		mk.On("APRequest", ticket, encyrptionKey, authenticator).Return(apRequest, nil)
		plugin := &Plugin{
			spn: "testing",
		}
		req, err := plugin.Attest(mk)
		assert.Nil(t, err)
		assert.NotEmpty(t, req)
	})

	t.Run("should fail login", func(t *testing.T) {
		mk := &mockKerberos{}

		mk.On("Login").Return(fmt.Errorf("error performing login"))

		plugin := &Plugin{
			spn: "testing",
		}
		req, err := plugin.Attest(mk)
		t.Log(err)
		assert.NotNil(t, err)
		assert.Empty(t, req)
	})

	t.Run("should fail getting service ticket", func(t *testing.T) {
		mk := &mockKerberos{}

		mk.On("Login").Return(nil)
		mk.On("GetServiceTicket", "testing").Return(nil, nil, fmt.Errorf("error getting service ticket"))

		plugin := &Plugin{
			spn: "testing",
		}
		req, err := plugin.Attest(mk)
		t.Log(err)
		assert.NotNil(t, err)
		assert.Empty(t, req)
	})
}
