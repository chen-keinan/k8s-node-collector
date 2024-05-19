# Node-Collector Specifications Design

## Define Compliance spec, based on cis benchmark or other specs

example:

```yaml
---
spec:
  id: k8s-cis
  title: CIS Kubernetes Benchmarks v1.23
  description: CIS Kubernetes Benchmarks
  version: '1.23'
  relatedResources:
  - https://www.cisecurity.org/benchmark/kubernetes
  controls:
  - id: 1.1.1
    name: Ensure that the API server pod specification file permissions are set to
      600 or more restrictive
    description: Ensure that the API server pod specification file has permissions
      of 600 or more restrictive
    audit:
      checks:
      - id: AVD-KCV-0073
      commands:
      - id: CMD-0001
    severity: HIGH
```

### Command Field

Specify the command ID (#ref) that needs to be executed to collect the information required to evaluate the control.

Example of how to define command data:

```yaml
---
- id: CMD-0001
  key: kubeletConfFilePermissions
  title: kubelet.conf file permissions
  nodeType: worker
  audit: stat -c %a $kubelet.kubeconfig
  platfrom:
    - k8s
    - aks
```

### Check Field

Specify the check that needs to be evaluated based on the information collected from the command data output to assess the control.

Example of how to define check data:

```sh
# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet.conf file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0073
#   avd_id: AVD-KCV-0073
#   severity: HIGH
#   short_code: ensure-kubelet.conf-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the kubelet.conf file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0073

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_file_permission(sp) := {"kubeletConfFilePermissions": violation} {
 sp.kind == "NodeInfo"
 sp.type == types[_]
 violation := {permission | permission = sp.info.kubeletConfFilePermissions.values[_]; permission > 600}
 count(violation) > 0
}

deny[res] {
 output := validate_kubelet_file_permission(input)
 msg := "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
 res := result.new(msg, output)
}
```

It is also require to a support to subtype node-info:

```yaml
subtypes:
 - kind: nodeinfo
```

### Command Config Files

The commands use a configuration file that helps obtain the paths to binaries and configuration files based on different platforms (e.g., Rancher, native Kubernetes, etc.).

For example:

```yaml
kubelet:
    bins:
      - kubelet
      - hyperkube kubelet
    confs:
      - /etc/kubernetes/kubelet-config.yaml
      - /var/lib/kubelet/config.yaml
```

### Commands Files Location

currently checks files location are :`https://github.com/aquasecurity/trivy-checks/tree/main/checks`

proposed command files location: `https://github.com/aquasecurity/trivy-checks/tree/main/commands`
under command file

Note: command config files will be located under `https://github.com/aquasecurity/trivy-checks/tree/main/commands` as well

### Download Commands Data

When Trivy downloads the checks database, it includes the following folder structure. It is proposed to include the commands files data:

```sh
  - content
      |- policies
           |- cloud
           |- docker
           |- kubernetes
      |- commands
           |- kubernetes  
```

### Preparing commands data for compliance report as input for node-colector

When the Trivy command is executed: `trivy k8s --compliance k8s-cis`, the relevant compliance specification will be parsed based on the spec name `k8s-cis` and `k8s_version`. It will build a list of command files to be passed to the node-collector, which will parse and execute them, returning the appropriate output.

### Auto detecting spec name and version

In cases where the specification name and version have not been specified, Trivy-Kubernetes will automatically detect the platform type and version.
 Based on this detection, the relevant specification will be identified according to the mapping data included in the configuration file.

mapping config example:

```yaml
k8s:
  - op: "="
    cluster_version: "1.21"
    spec: k8s-cis-1.21.0
  - op: ">"
    cluster_version: "1.21"
    spec: k8s-cis-1.23.0
```


### Preparing commands data for cluster infra assessments

When the Trivy command is executed: `trivy k8s --report summary`, the report will include a cluster infrastructure assessment.

Trivy-Kubernetes will detect the running platform, build a list of command files to be passed to the node-collector, which will parse and execute them, and return the appropriate output.

### Node-collector

The node collector will read commands and execute each command, and incorporate the output into the NodeInfo resource.

example:

```json
{
  "apiVersion": "v1",
  "kind": "NodeInfo",
  "metadata": {
    "creationTimestamp": "2023-01-04T11:37:11+02:00"
  },
  "type": "master",
  "info": {
    "adminConfFileOwnership": {
      "values": [
        "root:root"
      ]
    },
    "adminConfFilePermissions": {
      "values": [
        600
      ]
    }
    ...
  }
}
```
