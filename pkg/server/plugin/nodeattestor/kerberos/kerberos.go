package kerberos

import (
	common "github.com/spiffe/spire/pkg/common/plugin/kerberos"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
	gokrbservice "gopkg.in/jcmturner/gokrb5.v7/service"
)

type Kerberos interface {
	LoadKeyTab()
	LoadConfig()
	VerifyAPRequest(*gokrbkeytab.Keytab, *common.KrbAttestedData) (bool, *credentials.Credentials, error)
}

func GetKerberosProvider() (k Kerberos) {
	return &kerberos{}
}

// kerberos implements the Kerberos interface
type kerberos struct {
}

func (k *kerberos) LoadConfig() {

}

func (k *kerberos) LoadKeyTab() {}

func (k *kerberos) VerifyAPRequest(kt *gokrbkeytab.Keytab, attestedData *common.KrbAttestedData) (bool, *credentials.Credentials, error) {
	// Verify the AP (Authentication Protocol) request from SPIRE agent
	s := gokrbservice.NewSettings(kt)
	valid, creds, err := gokrbservice.VerifyAPREQ(attestedData.KrbAPReq, s)
	return valid, creds, err
}
