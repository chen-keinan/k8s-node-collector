package collector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNodeConfig(t *testing.T) {
	tests := []struct {
		name                   string
		nodeConfigFile         string
		expextedNodeConfigFile map[string]*Info
	}{
		{
			name:           "parse node config",
			nodeConfigFile: "./testdata/fixture/node_config.json",
			expextedNodeConfigFile: map[string]*Info{
				"kubeletAnonymousAuthArgumentSet": {
					Values: []interface{}{"false"},
				},
				"kubeletAuthorizationModeArgumentSet": {
					Values: []interface{}{"Webhook"},
				},
				"kubeletClientCaFileArgumentSet": {
					Values: []interface{}{"/etc/kubernetes/certs/ca.crt"},
				},
				"kubeletEventQpsArgumentSet": {
					Values: []interface{}{0.0},
				},
				"kubeletMakeIptablesUtilChainsArgumentSet": {
					Values: []interface{}{"true"},
				},
				"kubeletStreamingConnectionIdleTimeoutArgumentSet": {
					Values: []interface{}{"4h0m0s"},
				},
				"kubeletOnlyUseStrongCryptographic": {
					Values: []interface{}{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_RSA_WITH_AES_128_GCM_SHA256"},
				},
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.nodeConfigFile)
			assert.NoError(t, err)
			nodeConfig := make(map[string]interface{})
			err = json.Unmarshal(data, &nodeConfig)
			assert.NoError(t, err)
			m, err := getValuesFromkubeletConfig(nodeConfig)
			assert.NoError(t, err)
			for k, v := range m {
				if _, ok := tt.expextedNodeConfigFile[k]; ok {
					assert.Equal(t, v, tt.expextedNodeConfigFile[k])
				}
			}
		})
	}
}
