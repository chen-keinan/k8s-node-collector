# Contributing

These guidelines will help you get started with the k8s-Node-Collector project.

## Table of Contents

- [Contributing](#contributing)
  - [Table of Contents](#table-of-contents)
  - [Contribution Workflow](#contribution-workflow)
    - [Issues and Discussions](#issues-and-discussions)
    - [Pull Requests](#pull-requests)
      - [Conventional Commits](#conventional-commits)
  - [Set up your Development Environment](#set-up-your-development-environment)
  - [Build Binaries](#build-binaries)
    - [running node-collector binary](#running-node-collector-binary)
  - [Testing](#testing)
    - [Run unit Tests](#run-unit-tests)

## Contribution Workflow

### Issues and Discussions

- Feel free to open issues for any reason as long as you make it clear what this issue is about: bug/feature/proposal/comment.
- For questions and general discussions, please do not open an issue, and instead create a discussion in the "Discussions" tab.
- Please spend a minimal amount of time giving due diligence to existing issues or discussions. Your topic might be a duplicate. If it is, please add your comment to the existing one.
- Please give your issue or discussion a meaningful title that will be clear for future users.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.
- For technical questions, please explain in detail what you were trying to do, provide an error message if applicable, and your versions of k8s-node-collector and your environment.

### Pull Requests

- Every Pull Request should have an associated Issue unless it is a trivial fix.
- Your PR is more likely to be accepted if it focuses on just one change.
- Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that start with "fix"/"add"/"improve"/"remove" are good examples.
- There's no need to add or tag reviewers, if your PR is left unattended for too long, you can add a comment to bring it up to attention, optionally "@" mention one of the maintainers that was involved with the issue.
- If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it and re-request a review.
- When addressing comments, try to fix each suggestion in a separate commit.
- Tests are not required at this point as k8s-node-collector is evolving fast, but if you can include tests that will be appreciated.

#### Conventional Commits

It is not that strict, but we use the [Conventional commits](https://www.conventionalcommits.org) in this repository.
Each commit message doesn't have to follow conventions as long as it is clear and descriptive since it will be squashed and merged.

## Set up your Development Environment

- Install Go

   The project requires [Go 1.22.2][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
- Get the source code:

```sh
git clone git@github.com:aquasecurity/k8s-node-collector.git
cd k8s-node-collector
```

- Access to a Kubernetes cluster. We assume that you're using a [KIND][kind] cluster. To create a single-node KIND
   cluster, run:

```sh
kind create cluster
```

## Build Binaries

| Binary               | Image                                          | Description                                                   |
|----------------------|------------------------------------------------|---------------------------------------------------------------|
| `node-collector`     | `ghcr.io/aquasecurity/node-collector:dev`      | k8s-node-collector                                            |

To build node-collector binary, run:

```sh
make build
```

### running node-collector binary

when running node-collector binary it will run cis-spec based on version mapping define in [config.yaml](./pkg/collector/config/config.yaml)
or you can define you on spec by using the flag `--spec k8s-cis` and `--version 1.23.0`

```sh
node-collector --help

A tool which provide a way to extract file info which is not accessible via pre-define commands

Usage:
  node-collector [flags]
  node-collector [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  k8s         k8s-node-collector extract file system info from cluster Node

Flags:
  -h, --help             help for node-collector
  -n, --node string      node name
  -o, --output string    Output format. One of table|json (default "json")
  -s, --spec string       spec name. example: k8s-cis
  -v, --version string   spec version. example 1.23.0
```

This uses the `go build` command and builds binaries in the `./bin` directory.

To build all k8s-node-collector binary into Docker images, run:

copy `node-collector` binary to ./build/node-collector

```sh
 mv ./cmd/node-collector/node-collector ./build/node-collector/node-collector
```

build docker image

```sh
make build:docker
```

## Testing

We generally require tests to be added for all, but the most trivial of changes. However, unit tests alone don't
provide guarantees about the behaviour of k8s-node-collector. To verify that each Go module correctly interacts with its
collaborators, more coarse grained integration tests might be required.

### Run unit Tests

To run all tests with code coverage enabled, run:

```sh
make test
```

