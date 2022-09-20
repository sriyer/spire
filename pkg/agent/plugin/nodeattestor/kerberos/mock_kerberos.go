package kerberos

import (
	"github.com/stretchr/testify/mock"
	"gopkg.in/jcmturner/gokrb5.v7/crypto/etype"
	gokrbmsgs "gopkg.in/jcmturner/gokrb5.v7/messages"
	gokrbtypes "gopkg.in/jcmturner/gokrb5.v7/types"
)

type mockKerberos struct {
	mock.Mock
}

func (mk *mockKerberos) GetServiceTicket(spn string) (ticket gokrbmsgs.Ticket, key gokrbtypes.EncryptionKey, err error) {
	args := mk.Called(spn)
	if args.Get(0) != nil {
		ticket = args.Get(0).(gokrbmsgs.Ticket)
	}
	if args.Get(1) != nil {
		key = args.Get(1).(gokrbtypes.EncryptionKey)
	}

	return ticket, key, args.Error(2)
}
func (mk *mockKerberos) GetAuthenitcator(realm string, cname gokrbtypes.PrincipalName) (authenticator gokrbtypes.Authenticator, err error) {
	args := mk.Called(realm, cname)
	if args.Get(0) != nil {
		authenticator = args.Get(0).(gokrbtypes.Authenticator)
	}
	return authenticator, args.Error(1)
}
func (mk *mockKerberos) GetEncryptionType(keyType int32) (eType etype.EType, err error) {
	args := mk.Called(keyType)
	if args.Get(0) != nil {
		eType = args.Get(0).(etype.EType)
	}
	return eType, args.Error(1)
}
func (mk *mockKerberos) GetSequenceNumberAndSubKey(authenticator gokrbtypes.Authenticator, encryptionType etype.EType) error {
	args := mk.Called(authenticator, encryptionType)
	return args.Error(0)
}
func (mk *mockKerberos) APRequest(ticket gokrbmsgs.Ticket, sessionKey gokrbtypes.EncryptionKey, authenticator gokrbtypes.Authenticator) (apRequest gokrbmsgs.APReq, err error) {
	args := mk.Called(ticket, sessionKey, authenticator)
	if args.Get(0) != nil {
		apRequest = args.Get(0).(gokrbmsgs.APReq)
	}
	return apRequest, args.Error(1)
}

func (mk *mockKerberos) Login() (err error) {
	args := mk.Called()
	return args.Error(0)
}
func (mk *mockKerberos) Destroy() {
	mk.Called()
}
func (mk *mockKerberos) GetCredentialDomain() string {
	args := mk.Called()
	return args.String(0)
}
func (mk *mockKerberos) GetCredentialCName() (cname gokrbtypes.PrincipalName) {
	args := mk.Called()
	if args.Get(0) != nil {
		cname = args.Get(0).(gokrbtypes.PrincipalName)
	}
	return
}
