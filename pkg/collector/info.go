package collector

import (
	"embed"
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	configFolder = "config"
	// Version resource version
	Version = "v1"
	// Kind resource kind
	Kind = "NodeInfo"
)

//go:embed config/specs
var config embed.FS

//go:embed config
var params embed.FS

// LoadConfig load audit commands specification from config file
func LoadConfig(configMap map[string]string) (map[string]*SpecInfo, error) {
	fullPath := fmt.Sprintf("%s/%s", configFolder, "specs")
	dirEntries, err := config.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	specInfoMap := make(map[string]*SpecInfo)
	for _, entry := range dirEntries {
		fContent, err := config.ReadFile(fmt.Sprintf("%s/%s", fullPath, entry.Name()))
		if err != nil {
			return nil, err
		}
		updatedContent := string(fContent)
		for k, v := range configMap {
			updatedContent = strings.ReplaceAll(updatedContent, k, v)
		}
		si, err := getSpecInfo(updatedContent)
		if err != nil {
			return nil, err
		}
		specInfoMap[si.Name] = si
	}
	return specInfoMap, nil
}

// LoadConfigParams load audit params data
func LoadConfigParams(nodeFileconfig, specVersionMapping string) (*Config, *Mapper, error) {
	var decodedNodeFileconfig, decodedspecVersionMapping []byte
	var err error
	if nodeFileconfig != "" && specVersionMapping != "" {
		decodedNodeFileconfig, err = base64.StdEncoding.DecodeString(nodeFileconfig)
		if err != nil {
			return nil, nil, err
		}
		decodedspecVersionMapping, err = base64.StdEncoding.DecodeString(specVersionMapping)
		if err != nil {
			return nil, nil, err
		}
	} else {
		fullPath := fmt.Sprintf("%s/%s", configFolder, "config.yaml")
		decodedNodeFileconfig, err = params.ReadFile(fullPath)
		if err != nil {
			return nil, nil, err
		}
		decodedspecVersionMapping = decodedNodeFileconfig
	}
	return getNodeParams(string(decodedNodeFileconfig), string(decodedspecVersionMapping))
}

func LoadKubeletMapping(kubletConfigMapping string) (map[string]string, error) {
	var fContent []byte
	var err error
	if len(kubletConfigMapping) > 0 {
		fContent, err = base64.StdEncoding.DecodeString(kubletConfigMapping)
		if err != nil {
			return nil, err
		}
	} else {
		fullPath := fmt.Sprintf("%s/%s", configFolder, "kubeletconfig-mapping.yaml")
		fContent, err = params.ReadFile(fullPath)
		if err != nil {
			return nil, err
		}
	}
	mapping := make(map[string]string)
	err = yaml.Unmarshal(fContent, &mapping)
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

// SpecInfo spec info with require comand to collect
type SpecInfo struct {
	Version  string    `yaml:"version"`
	Name     string    `yaml:"name"`
	Title    string    `yaml:"title"`
	Commands []Command `yaml:"commands"`
}

// Collector details of info to collect
type Command struct {
	Key      string `yaml:"key"`
	Title    string `yaml:"title"`
	Audit    string `yaml:"audit"`
	NodeType string `yaml:"nodeType"`
}

func getSpecInfo(info string) (*SpecInfo, error) {
	var specInfo SpecInfo
	err := yaml.Unmarshal([]byte(info), &specInfo)
	if err != nil {
		return nil, err
	}
	return &specInfo, nil
}

func getNodeParams(config string, mapping string) (*Config, *Mapper, error) {
	var np Config
	err := yaml.Unmarshal([]byte(config), &np)
	if err != nil {
		return nil, nil, err
	}
	var mp Mapper
	err = yaml.Unmarshal([]byte(mapping), &mp)
	if err != nil {
		return nil, nil, err
	}
	return &np, &mp, nil
}

// Node output node data with info results
type Node struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
	Type       string            `json:"type"`
	Info       map[string]*Info  `json:"info"`
}

// Info comand output result
type Info struct {
	Values interface{} `json:"values"`
}

type Config struct {
	Node NodeParams `yaml:"node"`
}
type Mapper struct {
	VersionMapping map[string][]SpecVersion `yaml:"version_mapping"`
}
type SpecVersion struct {
	Name    string
	Version string `yaml:"cluster_version"`
	Op      string `yaml:"op"`
	CisSpec string `yaml:"spec"`
}
type NodeParams struct {
	APIserver         Params            `yaml:"apiserver"`
	ControllerManager Params            `yaml:"controllermanager"`
	Scheduler         Params            `yaml:"scheduler"`
	Etcd              Params            `yaml:"etcd"`
	Proxy             Params            `yaml:"proxy"`
	KubeLet           Params            `yaml:"kubelet"`
	Flanneld          Params            `yaml:"flanneld"`
	VersionMapping    map[string]string `yaml:"version_mapping"`
}

type Params struct {
	Config            []string `yaml:"confs,omitempty"`
	DefaultConfig     string   `yaml:"defaultconf,omitempty"`
	KubeConfig        []string `yaml:"kubeconfig,omitempty"`
	DefaultKubeConfig string   `yaml:"defaultkubeconfig,omitempty"`
	DataDirs          []string `yaml:"datadirs,omitempty"`
	DefaultDataDir    string   `yaml:"defaultdatadir,omitempty"`
	Binaries          []string `yaml:"bins,omitempty"`
	DefaultBinaries   string   `yaml:"defaultbins,omitempty"`
	Services          []string `yaml:"svc,omitempty"`
	DefalutServices   string   `yaml:"defaultsvc,omitempty"`
	CAFile            []string `yaml:"cafile,omitempty"`
	DefaultCAFile     string   `yaml:"defaultcafile,omitempty"`
}
