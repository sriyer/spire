package kerberos

import (
	gokrbclient "gopkg.in/jcmturner/gokrb5.v7/client"
	gokrbconfig "gopkg.in/jcmturner/gokrb5.v7/config"
	gokrbcrypto "gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/crypto/etype"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
	gokrbmsgs "gopkg.in/jcmturner/gokrb5.v7/messages"
	gokrbtypes "gopkg.in/jcmturner/gokrb5.v7/types"
)

type Kerberos interface {
	GetServiceTicket(spn string) (gokrbmsgs.Ticket, gokrbtypes.EncryptionKey, error)
	GetAuthenitcator(realm string, cname gokrbtypes.PrincipalName) (gokrbtypes.Authenticator, error)
	GetEncryptionType(keyType int32) (etype.EType, error)
	GetSequenceNumberAndSubKey(authenticator gokrbtypes.Authenticator, encryptionType etype.EType) error
	APRequest(ticket gokrbmsgs.Ticket, sessionKey gokrbtypes.EncryptionKey, authenticator gokrbtypes.Authenticator) (gokrbmsgs.APReq, error)
	Login() (err error)
	Destroy()
	GetCredentialDomain() string
	GetCredentialCName() gokrbtypes.PrincipalName
}

func GetKerberosWithKeytab(username, realm string, kt *gokrbkeytab.Keytab, krb5conf *gokrbconfig.Config, settings ...func(*gokrbclient.Settings)) Kerberos {
	client := gokrbclient.NewClientWithKeytab(username, realm, kt, krb5conf)
	return &kerberos{client: client}
}

type kerberos struct {
	client *gokrbclient.Client
}

func (k *kerberos) Destroy() {
	k.client.Destroy()
}

func (k *kerberos) Login() error {
	return k.client.Login()
}

func (k *kerberos) GetServiceTicket(spn string) (gokrbmsgs.Ticket, gokrbtypes.EncryptionKey, error) {
	return k.client.GetServiceTicket(spn)
}

func (k *kerberos) GetAuthenitcator(realm string, cname gokrbtypes.PrincipalName) (gokrbtypes.Authenticator, error) {
	return gokrbtypes.NewAuthenticator(realm, cname)
}

func (k *kerberos) GetEncryptionType(keyType int32) (etype.EType, error) {
	return gokrbcrypto.GetEtype(keyType)
}

func (k *kerberos) GetSequenceNumberAndSubKey(authenticator gokrbtypes.Authenticator, encryptionType etype.EType) error {
	return authenticator.GenerateSeqNumberAndSubKey(encryptionType.GetETypeID(), encryptionType.GetKeyByteSize())
}

func (k *kerberos) APRequest(ticket gokrbmsgs.Ticket, sessionKey gokrbtypes.EncryptionKey, authenticator gokrbtypes.Authenticator) (gokrbmsgs.APReq, error) {
	return gokrbmsgs.NewAPReq(ticket, sessionKey, authenticator)
}

func (k *kerberos) GetCredentialDomain() string {
	return k.client.Credentials.Domain()
}

func (k *kerberos) GetCredentialCName() gokrbtypes.PrincipalName {
	return k.client.Credentials.CName()
}
