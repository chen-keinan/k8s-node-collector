package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"fmt"
	"log"
	"path/filepath"

	"strconv"

	"github.com/Masterminds/semver"
	"github.com/spf13/cobra"
)

const (
	// Version is the version of the output
	defaultSpec = "k8s-cis-1.23.0"
)

// CollectData run spec audit command and output it result data
func CollectData(cmd *cobra.Command) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cluster, err := GetCluster()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(10)*time.Minute)
	defer cancel()

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Println("Increase --timeout value")
		}
	}()
	p, err := cluster.Platfrom()
	if err != nil {
		return err
	}
	shellCmd := NewShellCmd()
	nodeType, err := shellCmd.FindNodeType()
	if err != nil {
		return err
	}
	lp, err := LoadConfigParams()
	if err != nil {
		return err
	}
	cm := configParams(lp, shellCmd)
	infoCollectorMap, err := LoadConfig(cm)
	if err != nil {
		return err
	}
	specName := cmd.Flag("spec").Value.String()
	specVersion := cmd.Flag("version").Value.String()
	kubeletConfig := cmd.Flag("kubelet-config").Value.String()
	sv := fmt.Sprintf("%s-%s", specName, specVersion)
	if len(specName) == 0 || len(specVersion) == 0 {
		sv = specByPlatfromVersion(p, lp.VersionMapping)
	}
	for _, infoCollector := range infoCollectorMap {
		nodeInfo := make(map[string]*Info)
		if fmt.Sprintf("%s-%s", infoCollector.Name, infoCollector.Version) != sv {
			continue
		}
		for _, ci := range infoCollector.Collectors {
			if ci.NodeType != nodeType && nodeType != MasterNode {
				continue
			}
			output, err := shellCmd.Execute(ci.Audit)
			if err != nil {
				return err
			}
			values := StringToArray(output, ",")
			nodeInfo[ci.Key] = &Info{Values: values}
		}
		nodeName := cmd.Flag("node").Value.String()
		if nodeName != "" || kubeletConfig != "" {
			nodeConfig, err := loadNodeConfig(ctx, *cluster, nodeName, kubeletConfig)
			if err == nil {
				mapping, err := LoadKubeletMapping()
				if err != nil {
					return err
				}
				configVal := getValuesFromkubeletConfig(nodeConfig, mapping)
				mergeConfigValues(nodeInfo, configVal)
			}
		}
		nodeData := Node{
			APIVersion: Version,
			Kind:       Kind,
			Type:       nodeType,
			Metadata:   map[string]string{"creationTimestamp": time.Now().Format(time.RFC3339)},
			Info:       nodeInfo,
		}
		outputFormat := cmd.Flag("output").Value.String()
		err = printOutput(nodeData, outputFormat, os.Stdout)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadNodeConfig(ctx context.Context, cluster Cluster, nodeName string, kubeletConfig string) (map[string]interface{}, error) {
	var data []byte
	var err error
	if kubeletConfig != "" {
		data, err = base64.StdEncoding.DecodeString(kubeletConfig)
	} else {
		data, err = cluster.clientSet.RESTClient().Get().AbsPath(fmt.Sprintf("/api/v1/nodes/%s/proxy/configz", nodeName)).DoRaw(ctx)
	}
	if err != nil {
		return nil, err
	}
	nodeConfig := make(map[string]interface{})
	err = json.Unmarshal(data, &nodeConfig)
	if err != nil {
		return nil, err
	}
	return nodeConfig, nil
}

func specByPlatfromVersion(platfrom Platform, versionSpecMapper map[string][]SpecVersion) string {
	speVersions, ok := versionSpecMapper[platfrom.Name]
	if ok {
		for _, cisVer := range speVersions {
			c, err := semver.NewConstraint(fmt.Sprintf("%s %s", cisVer.Op, cisVer.Version))
			if err != nil {
				// default to basic k8s spec
				return defaultSpec
			}
			v, err := semver.NewVersion(platfrom.Version)
			if err != nil {
				// default to basic k8s spec
				return defaultSpec
			}
			if ok, _ = c.Validate(v); ok {
				return cisVer.CisSpec
			}
		}
	}
	return defaultSpec
}

func getValuesFromkubeletConfig(nodeConfig map[string]interface{}, configMapper map[string]string) map[string]*Info {
	overrideConfig := make(map[string]*Info)
	values := nodeConfig["kubeletconfig"]
	for k, v := range configMapper {
		p := values
		var found bool
		paramValue := strings.TrimPrefix(v, "kubeletconfig.")
		splittedValues := StringToArray(paramValue, ".")
		for _, sv := range splittedValues {
			next := p.(map[string]interface{})
			if k, ok := next[sv.(string)]; ok {
				found = true
				p = k
			} else {
				found = false
			}
		}
		if found {
			switch r := p.(type) {
			case bool:
				overrideConfig[k] = &Info{Values: []interface{}{strconv.FormatBool(r)}}
			case []interface{}:
				overrideConfig[k] = &Info{Values: r}
			default:
				overrideConfig[k] = &Info{Values: []interface{}{r}}
			}
		}
	}
	return overrideConfig
}

func mergeConfigValues(configValues map[string]*Info, overrideConfig map[string]*Info) map[string]*Info {
	for k, v := range overrideConfig {
		configValues[k] = v
	}
	return configValues
}

func binLookup(binsNames []string, defaultBinName string, sh Shell) string {
	if len(binsNames) == 0 {
		return ""
	}
	for _, bin := range binsNames {
		cmd := fmt.Sprintf(`pgrep -l "" | grep '%s' | awk '{print $2}' | awk 'NR==1' 2>/dev/null`, bin)
		name, err := sh.Execute(cmd)
		if err != nil {
			return defaultBinName
		}
		if strings.TrimSpace(name) != "" {
			return filepath.Base(name)
		}
	}
	return defaultBinName
}

func configLookup(configNames []string, defaultConfigName string, sh Shell) string {
	if len(configNames) == 0 {
		return ""
	}
	for _, config := range configNames {
		configCms := fmt.Sprintf(`ls %s 2>/dev/null | awk 'NR==1'`, config)
		cmdConfig, err := sh.Execute(configCms)
		if err != nil {
			return defaultConfigName
		}
		if strings.TrimSpace(cmdConfig) != "" {
			return cmdConfig
		}
	}
	return defaultConfigName
}

func configData(param Params, sh Shell, binName string, paramMaps map[string]string) {
	bins := binLookup(param.Binaries, param.DefaultBinaries, sh)
	if bins != "" {
		paramMaps[fmt.Sprintf("$%s.bins", binName)] = bins
	}
	confs := configLookup(param.Config, param.DefaultConfig, sh)
	if confs != "" {
		paramMaps[fmt.Sprintf("$%s.confs", binName)] = confs
	}
	kubeConfig := configLookup(param.KubeConfig, param.DefaultKubeConfig, sh)
	if kubeConfig != "" {
		paramMaps[fmt.Sprintf("$%s.kubeconfig", binName)] = kubeConfig
	}
	dataDir := folderLookup(param.DataDirs, param.DefaultDataDir, sh)
	if dataDir != "" {
		paramMaps[fmt.Sprintf("$%s.datadirs", binName)] = dataDir
	}
	services := configLookup(param.Services, param.DefalutServices, sh)
	if services != "" {
		paramMaps[fmt.Sprintf("$%s.svc", binName)] = services
	}
	CAFile := folderLookup(param.CAFile, param.DefaultCAFile, sh)
	if CAFile != "" {
		paramMaps[fmt.Sprintf("$%s.cafile", binName)] = CAFile
	}
}

func folderLookup(paths []string, defaultFolder string, sh Shell) string {
	path := configLookup(paths, defaultFolder, sh)
	if path == "" {
		return ""
	}
	return filepath.Dir(path)
}

func configParams(config *Config, sh Shell) map[string]string {
	mapParams := make(map[string]string)
	configData(config.Node.APIserver, sh, "apiserver", mapParams)
	configData(config.Node.ControllerManager, sh, "controllermanager", mapParams)
	configData(config.Node.Scheduler, sh, "scheduler", mapParams)
	configData(config.Node.Etcd, sh, "etcd", mapParams)
	configData(config.Node.Proxy, sh, "proxy", mapParams)
	configData(config.Node.KubeLet, sh, "kubelet", mapParams)
	configData(config.Node.Flanneld, sh, "flanneld", mapParams)
	return mapParams
}
