# nnf-storedversions-maint

Nnf-storedversions-maint maintains the `status.storedVersions` list in certain CustomResourceDefinitions (CRD), and is used together with [kube-storage-version-migrator](https://github.com/NearNodeFlash/kube-storage-version-migrator/tree/nnf-main) (see the `nnf-main` branch there). The **kube-storage-version-migrator** service migrates the resources of a CRD to the latest `storage` version of that CRD, and **nnf-storedversions-maint** then updates the `storedVersions` list in the CRD to remove the unused API versions. This maintenance is necessary to allow older API versions to be removed during future upgrades of those CRDs.

This tool maintains the CRDs in the `nnf.cray.hpe.com`, `lus.cray.hpe.com`, and `dataworkflowservices.github.io` groups.

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.26.5 — see [Go toolchain](#go-toolchain) below
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### Go toolchain

The manager is built with **exactly Go 1.26.5**, the latest release the customer supports.
That version is pinned in three places and they must move together:

- `go.mod` — the `go 1.26.5` directive. CI's `setup-go` reads this file, so CI builds with 1.26.5.
- `Dockerfile` — `FROM docker.io/golang:1.26.5`, with `GOTOOLCHAIN=local` so the build fails
  loudly instead of auto-downloading a newer toolchain if `go.mod` is ever bumped past the image.
- `.devcontainer/devcontainer.json` — same image.

Do not use the floating `golang:1.26` tag; it already resolves to a later patch release.

A `toolchain` directive cannot serve as the pin: `go mod tidy` removes it when it matches the `go`
line. The shipped artifact is the Docker image, so that is where the pin is enforced. Local builds
on a machine with a newer Go will use the newer toolchain under the default `GOTOOLCHAIN=auto`; run
`GOTOOLCHAIN=go1.26.5 make build` to reproduce the release build exactly.

**Known residual:** `govulncheck ./...` reports Go standard-library advisories that are fixed in
go1.26.6 (`net/url`, `crypto/tls`, `net/http`, `encoding/asn1`, and the `idna` check in
`net/http`). These cannot be addressed by a module bump; they clear only when the supported Go
version moves. They are not Dependabot alerts (Dependabot does not track the standard library), so
re-run `govulncheck` when re-evaluating the pin.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/nnf-storedversions-maint VERSION=tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/nnf-storedversions-maint VERSION=tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Metrics

The controller-runtime metrics endpoint is **disabled**. Nothing in NNF scrapes it, and the
Kubebuilder-scaffolded authn/authz filter that protected it
(`filters.WithAuthenticationAndAuthorization`) linked `k8s.io/apiserver`, `cel-go`, `antlr`,
`konnectivity-client`, OpenTelemetry and `google.golang.org/grpc` into the manager. That added 27
module requirements and roughly 37MB of binary for code that was never executed, and it was the
source of most of this repo's recurring Dependabot advisories.

Nothing was deleted — the manifests and the e2e test are still present, just commented out or
skipped. To re-enable:

1. `cmd/main.go` — restore the import `"sigs.k8s.io/controller-runtime/pkg/metrics/filters"` and,
   after `metricsServerOptions` is built, restore:

   ```go
   if secureMetrics {
       metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
   }
   ```

   Skipping this step leaves `:8443` unauthenticated; in that case enable `../network-policy`
   in step 2 as well, so only namespaces labeled `metrics: enabled` can reach it.
2. `config/default/kustomization.yaml` — uncomment `- metrics_service.yaml`, and the `patches:` key
   together with its `manager_metrics_patch.yaml` entry (that patch passes
   `--metrics-bind-address=:8443`; the manager's default is `0`, meaning off).
3. `config/rbac/kustomization.yaml` — uncomment `metrics_auth_role.yaml`,
   `metrics_auth_role_binding.yaml` and `metrics_reader_role.yaml`.
4. `test/e2e/e2e_test.go` — drop the `Skip(...)` at the top of
   "should ensure the metrics endpoint is serving metrics".
5. Run `go mod tidy && go mod vendor` to pull the dependency tree back in.

For Prometheus scraping and cert-manager-issued serving certs, also uncomment the `[PROMETHEUS]`
and `[METRICS-WITH-CERTS]` sections in `config/default/kustomization.yaml`.

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/nnf-storedversions-maint VERSION=tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/nnf-storedversions-maint/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

