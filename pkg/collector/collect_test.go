package collector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/kustomize/kyaml/yaml"
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
			mapping, err := LoadKubeletMapping()
			assert.NoError(t, err)
			m := getValuesFromkubeletConfig(nodeConfig, mapping)
			for k, v := range m {
				if _, ok := tt.expextedNodeConfigFile[k]; ok {
					assert.Equal(t, v, tt.expextedNodeConfigFile[k])
				}
			}
		})
	}
}

func TestSpecByVersionName(t *testing.T) {
	tests := []struct {
		name               string
		versionMappingfile string
		platfrom           Platform
		wantSpec           string
	}{
		{
			name:               "k8s cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "k8s", Version: "1.21"},
			wantSpec:           "k8s-cis-1.23.0",
		},
		{
			name:               "aks cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "aks", Version: "1.21"},
			wantSpec:           "aks-cis-1.0.0",
		},
		{
			name:               "eks cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "eks", Version: "1.21"},
			wantSpec:           "eks-cis-1.2.0",
		},
		{
			name:               "gke cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "gke", Version: "1.21"},
			wantSpec:           "gke-cis-1.2.0",
		},
		{
			name:               "rke2 cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "rke2", Version: "1.21"},
			wantSpec:           "rke2-cis-1.24.0",
		},
		{
			name:               "ocp cis spec",
			versionMappingfile: "./testdata/fixture/mapping.yaml",
			platfrom:           Platform{Name: "ocp", Version: "4.0"},
			wantSpec:           "rh-cis-1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.ReadFile(tt.versionMappingfile)
			assert.NoError(t, err)
			var config Config
			err = yaml.Unmarshal(f, &config)
			assert.NoError(t, err)
			gotSpec := specByPlatfromVersion(tt.platfrom, config.VersionMapping)
			assert.Equal(t, gotSpec, tt.wantSpec)
		})
	}
}

func TestPlatfromVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "k8s version",
			version: "v1.23.2",
			want:    "1.23",
		},
		{
			name:    "eks version",
			version: "v1.23.17-eks-8ccc7ba",
			want:    "1.23",
		},
		{
			name:    "aks version",
			version: "v1.23.17-eks-8ccc7ba",
			want:    "1.23",
		},
		{
			name:    "gke version",
			version: "v1.23.10-gke.2300",
			want:    "1.23",
		},
		{
			name:    "rke2 version",
			version: "v1.23.11+rke2r1",
			want:    "1.23",
		},
		{
			name:    "ocp version",
			version: "v1.23.15+c763d11",
			want:    "1.23",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPlatformInfoFromVersion(tt.version)
			assert.Equal(t, got.Version, tt.want)
		})
	}
}
