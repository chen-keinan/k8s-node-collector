package main

import (
	"bytes"
	"encoding/base64"
	"os"

	"github.com/dsnet/compress/bzip2"
	"gopkg.in/yaml.v3"
	batchv1 "k8s.io/api/batch/v1"
)

func main() {
	// This test is to verify that the args update works as expected
	// and that the new args are reflected in the pod

	var job batchv1.Job

	j, err := os.ReadFile("./tests/e2e/job.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(j, &job)
	if err != nil {
		panic(err)
	}
	for index, arg := range job.Spec.Template.Spec.Containers[0].Args {
		switch arg {
		case "--kubelet-config":
			cc, err := os.ReadFile("./tests/e2e/kubeletconfig.json")
			if err != nil {
				panic(err)
			}
			cce, err := CompressAndEncode(cc)
			if err != nil {
				panic(err)
			}
			job.Spec.Template.Spec.Containers[0].Args[index+1] = cce

		case "--kubelet-config-mapping":
			cc, err := os.ReadFile("./tests/e2e/kubeletconfig-mapping.yaml")
			if err != nil {
				panic(err)
			}
			cce, err := CompressAndEncode(cc)
			if err != nil {
				panic(err)
			}
			job.Spec.Template.Spec.Containers[0].Args[index+1] = cce

		case "--node-config":
			cc, err := os.ReadFile("./tests/e2e/nodeconfig.yaml")
			if err != nil {
				panic(err)
			}
			cce, err := CompressAndEncode(cc)
			if err != nil {
				panic(err)
			}
			job.Spec.Template.Spec.Containers[0].Args[index+1] = cce

		case "--node-commands":
			cc, err := os.ReadFile("./tests/e2e/commands.yaml")
			if err != nil {
				panic(err)
			}
			cce, err := CompressAndEncode(cc)
			if err != nil {
				panic(err)
			}
			job.Spec.Template.Spec.Containers[0].Args[index+1] = cce
		}
	}
	job.APIVersion = "batch/v1"
	job.Kind = "Job"
	b, err := yaml.Marshal(job)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("./tests/e2e/job-update.yaml", b, 0600)
	if err != nil {
		panic(err)
	}
}

func bzip2Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := bzip2.NewWriter(&buf, &bzip2.WriterConfig{Level: bzip2.DefaultCompression})
	if err != nil {
		return []byte{}, err
	}

	_, err = w.Write(data)
	if err != nil {
		return []byte{}, err
	}
	w.Close()
	return buf.Bytes(), nil
}

func CompressAndEncode(data []byte) (string, error) {
	cm, err := bzip2Compress(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cm), nil
}
