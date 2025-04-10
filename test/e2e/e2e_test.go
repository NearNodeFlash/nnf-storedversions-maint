/*
 * Copyright 2025 Hewlett Packard Enterprise Development LP
 * Other additional copyright holders may be indicated within.
 *
 * The entirety of this work is licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/NearNodeFlash/nnf-storedversions-maint/test/utils"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	zapcr "sigs.k8s.io/controller-runtime/pkg/log/zap"

	v42alpha1 "github.com/NearNodeFlash/nnf-storedversions-maint/test/e2e/release1/api/v42alpha1"
	v42alpha2 "github.com/NearNodeFlash/nnf-storedversions-maint/test/e2e/release2/api/v42alpha2"
	v42alpha3 "github.com/NearNodeFlash/nnf-storedversions-maint/test/e2e/release3/api/v42alpha3"
	// +kubebuilder:scaffold:imports
)

// namespace where the project is deployed in
const namespace = "nnf-storedversions-maint-system"

// serviceAccountName created for the project
const serviceAccountName = "nnf-storedversions-maint-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "nnf-storedversions-maint-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "nnf-storedversions-maint-metrics-binding"

var (
	scheme = runtime.NewScheme()
)

const (
	svmCrdName     = "SvmTest"
	svmCrdGroup    = "nnf.cray.hpe.com"
	svmCrdRelease1 = "v42alpha1"
	svmCrdRelease2 = "v42alpha2"
	svmCrdRelease3 = "v42alpha3"
)

var (
	svmCrdNamePlural = strings.ToLower(svmCrdName) + "s"
	svmCrdFullName   = svmCrdNamePlural + "." + svmCrdGroup
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func setupLog() logr.Logger {
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	zaplogger := zapcr.New(zapcr.Encoder(encoder), zapcr.UseDevMode(true))
	ctrl.SetLogger(zaplogger)

	// controllerruntime logger.
	log := ctrl.Log.WithName("e2e")
	return log
}

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string
	var k8sClient client.Client
	var config *rest.Config
	// var log logr.Logger
	var latestRelease int

	BeforeAll(func() {
		By("creating a k8s client")
		/* log */ _ = setupLog()
		config = ctrl.GetConfigOrDie()
		var err error
		k8sClient, err = client.New(config, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes client")
		latestRelease = 0
	})

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		// By("installing CRDs")
		// cmd = exec.Command("make", "install")
		// _, err = utils.Run(cmd)
		// Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		// By("uninstalling CRDs")
		// cmd = exec.Command("make", "uninstall-for-tests")
		// _, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {

		AfterEach(func() {
			By("cleaning up the metrics role binding")
			cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName)
			_, _ = utils.Run(cmd)
		})

		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=nnf-storedversions-maint-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccount": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput := getMetricsOutput()
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	}) // Context("Manager")

	Context("Migration Activity", Ordered, func() {

		BeforeAll(func() {
			removeStorageVersionMigration(svmCrdFullName)

			By("installing CRDs for release1")
			latestRelease = 1
			cmd := exec.Command("make", "install-test-release1")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs for release1")

			By("waiting for the CRD to be established")
			time.Sleep(5 * time.Second)
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "crd", svmCrdFullName)
				output, err := utils.Run(cmd)
				if err == nil && output != "" {
					return nil
				}
				return fmt.Errorf("CRD %s not found", svmCrdFullName)
			}).Should(Succeed(), "CRD should be established")

			bumpStorageVersionMigrationTrigger()

			utilruntime.Must(v42alpha1.AddToScheme(scheme))
		})

		AfterAll(func() {
			specReport := CurrentSpecReport()
			if specReport.Failed() {
				By("Fetching CRD resource")
				crd := getCRD(k8sClient, svmCrdFullName)
				_, _ = fmt.Fprintf(GinkgoWriter, "CRD name: %s\n", crd.Name)
				_, _ = fmt.Fprintf(GinkgoWriter, "CRD resource version: %s\n", crd.GetResourceVersion())
				_, _ = fmt.Fprintf(GinkgoWriter, "CRD generation: %d\n", crd.GetGeneration())
				_, _ = fmt.Fprintf(GinkgoWriter, "CRD stored versions: %v\n", crd.Status.StoredVersions)

				By("Fetching StorageVersionMigration resource")
				svmName := findStorageVersionMigration(svmCrdFullName)
				cmd := exec.Command("kubectl", "get", "storageversionmigration", svmName, "-o", "yaml")
				svmResource, err := utils.Run(cmd)
				if err == nil {
					_, _ = fmt.Fprintf(GinkgoWriter, "StorageVersionMigration resource:\n %s", svmResource)
				} else {
					_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get StorageVersionMigration resource: %s", err)
				}

				By("Fetching StorageState resource")
				cmd = exec.Command("kubectl", "get", "storagestate", svmCrdFullName, "-o", "yaml")
				stgStateResource, err := utils.Run(cmd)
				if err == nil {
					_, _ = fmt.Fprintf(GinkgoWriter, "StorageState resource:\n %s", stgStateResource)
				} else {
					_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get StorageState resource: %s", err)
				}
			}

			removeStorageVersionMigration(svmCrdFullName)

			By("uninstalling CRDs for release")
			if latestRelease > 0 {
				cmd := exec.Command("make", fmt.Sprintf("uninstall-test-release%d", latestRelease))
				_, _ = utils.Run(cmd)
				latestRelease = 0
			}
		})

		It("should find the CRD with original storedVersions when it has only one version", func() {
			By("getting the CRD")
			crd := getCRD(k8sClient, svmCrdFullName)

			By("waiting on the StorageVersionMigration resource")
			waitForStorageMigration(crd)

			By("re-examine the CRD")
			crd = waitForCRDResourceVersionToNotChange(k8sClient, crd)

			By("expecting one stored version, want " + svmCrdRelease1)
			Expect(crd.Status.StoredVersions).To(HaveLen(1), "CRD should have one stored version")
			Expect(crd.Status.StoredVersions[0]).To(Equal(svmCrdRelease1), "CRD stored version should match")
		})

		Context("Migration to release 2", Ordered, func() {

			BeforeAll(func() {
				By("pause between releases")
				time.Sleep(5 * time.Second)
				By("installing CRDs for release2")
				latestRelease = 2
				cmd := exec.Command("make", "install-test-release2")
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs for release2")
				By("waiting for the CRD to be established")
				time.Sleep(5 * time.Second)

				bumpStorageVersionMigrationTrigger()

				utilruntime.Must(v42alpha2.AddToScheme(scheme))
			})

			It("should find the CRD with new storedVersions when it has two versions", func() {
				By("getting the CRD")
				crd := getCRD(k8sClient, svmCrdFullName)

				By("waiting on the StorageVersionMigration resource")
				waitForStorageMigration(crd)

				By("re-examine the CRD")
				crd = waitForCRDResourceVersionBump(k8sClient, crd)

				By("expecting one stored version, want " + svmCrdRelease2)
				Expect(crd.Status.StoredVersions).To(HaveLen(1), "CRD should have one stored version")
				Expect(crd.Status.StoredVersions[0]).To(Equal(svmCrdRelease2), "CRD stored version should match")
			})

			Context("Migration to release 3", Ordered, func() {

				BeforeAll(func() {
					By("pause between releases")
					time.Sleep(5 * time.Second)
					By("installing CRDs for release3")
					latestRelease = 3
					cmd := exec.Command("make", "install-test-release3")
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs for release3")
					By("waiting for the CRD to be established")
					time.Sleep(5 * time.Second)

					bumpStorageVersionMigrationTrigger()

					utilruntime.Must(v42alpha3.AddToScheme(scheme))
				})

				It("should find the CRD with new storedVersions when it has three versions", func() {
					By("getting the CRD")
					crd := getCRD(k8sClient, svmCrdFullName)

					By("waiting on the StorageVersionMigration resource")
					waitForStorageMigration(crd)

					By("re-examine the CRD")
					crd = waitForCRDResourceVersionBump(k8sClient, crd)

					By("expecting one stored version, want " + svmCrdRelease3)
					Expect(crd.Status.StoredVersions).To(HaveLen(1), "CRD should have one stored version")
					Expect(crd.Status.StoredVersions[0]).To(Equal(svmCrdRelease3), "CRD stored version should match")
				})
			}) // Context("Migration to release 3")

		}) // Context("Migration to release 2")

	}) // Context("Migration Activity")
})

func waitForCRDResourceVersionBump(k8sClient client.Client, crd *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinition {
	GinkgoHelper()
	By("WAITING **UP TO 3 MINUTES** for the CRD resource version to change")
	var freshCrd *apiextensionsv1.CustomResourceDefinition = nil
	beforeVer := crd.GetResourceVersion()
	By("before resource version " + beforeVer)
	Eventually(func() string {
		By("waiting for CRD resource version to change")
		freshCrd = getCRD(k8sClient, crd.Name)
		By("found resource version " + freshCrd.GetResourceVersion())
		return freshCrd.GetResourceVersion()
	}).Within(3*time.Minute).ProbeEvery(20*time.Second).ShouldNot(Equal(beforeVer), "CRD resource version should change")
	return freshCrd
}

func waitForCRDResourceVersionToNotChange(k8sClient client.Client, crd *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinition {
	GinkgoHelper()
	By("WAITING **2 MINUTES** to confirm that the CRD resource version does not change")
	var freshCrd *apiextensionsv1.CustomResourceDefinition = nil
	beforeVer := crd.GetResourceVersion()
	By("before resource version " + beforeVer)
	Consistently(func() string {
		By("watching for CRD resource version to not change")
		freshCrd = getCRD(k8sClient, crd.Name)
		By("found resource version " + freshCrd.GetResourceVersion())
		return freshCrd.GetResourceVersion()
	}).Within(2*time.Minute).ProbeEvery(20*time.Second).Should(Equal(beforeVer), "CRD resource version should not change")
	return freshCrd
}

func getCRD(k8sClient client.Client, crdName string) *apiextensionsv1.CustomResourceDefinition {
	GinkgoHelper()
	crd := &apiextensionsv1.CustomResourceDefinition{}
	err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: crdName}, crd)
	Expect(err).NotTo(HaveOccurred(), "Failed to get CRD for test")
	Expect(crd).NotTo(BeNil(), "CRD should not be nil")
	return crd
}

func getStorageVersionFromCRD(crd *apiextensionsv1.CustomResourceDefinition) string {
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Storage {
			return crd.Spec.Versions[i].Name
		}
	}
	return ""
}

func removeStorageVersionMigration(crdName string) {
	By("removing existing storage-version-migrator StorageState resource")
	cmd := exec.Command("kubectl", "delete", "storagestate", crdName)
	_, _ = utils.Run(cmd)

	By("removing existing storage-version-migrator StorageVersionMigration resource")
	migrationResource := findStorageVersionMigration(crdName)
	if migrationResource != "" {
		By(fmt.Sprintf("removing StorageVersionMigration %s", migrationResource))
		cmd := exec.Command("kubectl", "delete", "storageversionmigration", migrationResource)
		_, _ = utils.Run(cmd)
	}
}

func findStorageVersionMigration(crdName string) string {
	kcmd := strings.Split("kubectl get storageversionmigrations --no-headers -o custom-columns=NAME:.metadata.name", " ")
	cmdList := exec.Command(kcmd[0], kcmd[1:]...)
	output, err := utils.Run(cmdList)
	if err == nil {
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, crdName) {
				return line
			}
		}
	}
	return ""
}

func bumpStorageVersionMigrationTrigger() {
	GinkgoHelper()
	// Scale the "trigger" deployment to 0 replicas and back to 1.
	// This will trigger the StorageVersionMigration controller to run now,
	// rather than waiting for its 10-minute resync period.
	namespace := "kube-system"
	By("bouncing the storage-version-migrator trigger deployment")
	cmd := exec.Command("kubectl", "scale", "deployment", "trigger",
		"--replicas=0", "-n", namespace)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to scale down trigger deployment")
	cmd = exec.Command("kubectl", "scale", "deployment", "trigger",
		"--replicas=1", "-n", namespace)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to scale up trigger deployment")

	By("waiting for trigger deployment to be ready")
	cmd = exec.Command("kubectl", "wait", "deployment", "trigger",
		"-n", namespace, "--for", "jsonpath={.status.availableReplicas}=1")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to wait for trigger deployment to be ready")
}

func waitForStorageMigration(crd *apiextensionsv1.CustomResourceDefinition) {
	GinkgoHelper()
	By("WAITING **UP TO 3 MINUTES** for the StorageVersionMigration resource to appear and be complete")
	// Note that the storage-version-migrator controller runs on a 10-minute
	// interval. We're using a shorter time because we expect that the trigger deployment
	// has been bumped.
	apiStorageVersion := getStorageVersionFromCRD(crd)
	migrationResource := ""
	Eventually(func() error {
		// We have to keep looking for the name of the StorageVersionMigration
		// resource, because it gets replaced with a resource of a new name each
		// time the storage-version-migrator works on a CRD.
		By("checking for StorageVersionMigration resource...")
		migrationResource = findStorageVersionMigration(crd.Name)
		if migrationResource == "" {
			return fmt.Errorf("StorageVersionMigration not found")
		}

		By("waiting for completion of StorageVersionMigration " + migrationResource)
		cmd := exec.Command("kubectl", "get", "storageversionmigrations", migrationResource, "-o", "json")
		output, err := utils.Run(cmd)
		if err == nil && output != "" {
			var result map[string]interface{}
			err = json.Unmarshal([]byte(output), &result)
			if err != nil {
				return fmt.Errorf("failed to unmarshal JSON: %v", err)
			}

			// Check if the API version in .spec.resource.version is the same as the CRD API storage version.
			specResource, ok := result["spec"].(map[string]interface{})["resource"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("failed to find spec.resource in JSON output")
			}
			resourceVersion, ok := specResource["version"].(string)
			if !ok {
				return fmt.Errorf("failed to find spec.resource.version in JSON output")
			}
			if resourceVersion != apiStorageVersion {
				return fmt.Errorf("StorageVersionMigration resource version %s does not match CRD storage version %s", resourceVersion, apiStorageVersion)
			}

			// Check if the status conditions array has a condition with type "Succeeded" and status "True"
			if _, ok := result["status"]; !ok {
				return fmt.Errorf("failed to find status in JSON output")
			}
			conditions, ok := result["status"].(map[string]interface{})["conditions"].([]interface{})
			if !ok {
				return fmt.Errorf("failed to find conditions in JSON output")
			}
			for _, condition := range conditions {
				cond, ok := condition.(map[string]interface{})
				if !ok {
					return fmt.Errorf("failed to convert condition to map")
				}
				if cond["type"] == "Succeeded" {
					if cond["status"] == "True" {
						// Happiness
						return nil
					}
				}
			}
			return fmt.Errorf("StorageVersionMigration not complete")
		}
		return fmt.Errorf("StorageVersionMigration not ready to be checked")
	}).Within(3*time.Minute).ProbeEvery(5*time.Second).Should(Succeed(), "StorageVersionMigration should be complete")

}

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
