package kerberos

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"

	gokrbconfig "gopkg.in/jcmturner/gokrb5.v7/config"
	gokrbcreds "gopkg.in/jcmturner/gokrb5.v7/credentials"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/idutil"
	common "github.com/spiffe/spire/pkg/common/plugin/kerberos"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
)

type Config struct {
	KrbRealm      string `hcl:"krb_realm"`
	KrbConfPath   string `hcl:"krb_conf_path"`
	KrbKeytabPath string `hcl:"krb_keytab_path"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	base.Base
	Kerberos
	mu          sync.Mutex
	log         hclog.Logger
	realm       string
	krbConfig   *gokrbconfig.Config
	keytab      *gokrbkeytab.Keytab
	trustDomain string
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) spiffeID(krbCreds *gokrbcreds.Credentials) (id string, err error) {
	spiffePath := path.Join("/", common.PluginName, krbCreds.Domain(), krbCreds.DisplayName())
	// id := &url.URL{
	// 	Scheme: defaultSpiffeScheme,
	// 	Host:   p.trustDomain,
	// 	Path:   spiffePath,
	// }
	td, err := spiffeid.TrustDomainFromString(p.trustDomain)
	if err != nil {
		return id, err
	}
	sID, err := idutil.AgentID(td, spiffePath)
	return sID.String(), err
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	agentID, selectors, err := p.attestRequest(req)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       agentID,
				SelectorValues: selectors,
			},
		},
	})
}

func (p *Plugin) attestRequest(req *nodeattestorv1.AttestRequest) (agentID string, selectors []string, err error) {
	attestedData := new(common.KrbAttestedData)
	if e := json.Unmarshal(req.GetPayload(), attestedData); e != nil {
		err = common.PluginErr.New("unmarshaling KRB_AP_REQ from attestation data: %v", e)
		return
	}

	valid, creds, e := p.VerifyAPRequest(p.keytab, attestedData)
	if e != nil {
		err = common.PluginErr.New("validating KRB_AP_REQ: %v", e)
		return
	}

	if !valid {
		err = common.PluginErr.New("failed to validate KRB_AP_REQ")
		return
	}
	agentID, err = p.spiffeID(creds)
	if err != nil {
		err = common.PluginErr.New("Error creating spiffie ID: %v", err)
		return
	}
	selectors = buildSelectors(creds.CName().PrincipalNameString())
	return agentID, selectors, err
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, common.PluginErr.New("unable to decode configuration: %v", err)
	}

	if req.GetCoreConfiguration() == nil {
		return nil, common.PluginErr.New("global configuration is required")
	}

	if req.GetCoreConfiguration().GetTrustDomain() == "" {
		return nil, common.PluginErr.New("trust_domain is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	krbCfg, err := gokrbconfig.Load(config.KrbConfPath)
	if err != nil {
		return nil, common.PluginErr.New("error loading Kerberos config: %v", err)
	}

	krbKt, err := gokrbkeytab.Load(config.KrbKeytabPath)
	if err != nil {
		return nil, common.PluginErr.New("error loading Kerberos keytab: %v", err)
	}

	p.realm = config.KrbRealm
	p.krbConfig = krbCfg
	p.keytab = krbKt
	p.trustDomain = req.GetCoreConfiguration().GetTrustDomain()

	return &configv1.ConfigureResponse{}, nil
}

func buildSelectors(principalName string) []string {
	return []string{fmt.Sprintf("pn:%s", principalName)}
}
