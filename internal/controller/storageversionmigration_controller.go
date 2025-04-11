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

package controller

import (
	"context"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	migrationv1alpha1 "sigs.k8s.io/kube-storage-version-migrator/pkg/apis/migration/v1alpha1"
	migrationpkg "sigs.k8s.io/kube-storage-version-migrator/pkg/controller"
)

// StorageVersionMigrationReconciler reconciles a StorageVersionMigration object
type StorageVersionMigrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=migration.k8s.io,resources=storageversionmigrations,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.k8s.io,resources=storageversionmigrations/status,verbs=get
// +kubebuilder:rbac:groups=migration.k8s.io,resources=storagestates,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.k8s.io,resources=storagestates/status,verbs=get
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions/status,verbs=get;update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the StorageVersionMigration object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *StorageVersionMigrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.Log.WithName("storage-version-maint").WithValues("name", req.NamespacedName)

	svm := &migrationv1alpha1.StorageVersionMigration{}
	if err := r.Get(ctx, req.NamespacedName, svm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the object is being deleted
	if !svm.DeletionTimestamp.IsZero() {
		// We'll be back after the next run of storage-version-migrator.
		// It replaces this resource on each iteration.
		log.V(3).Info("StorageVersionMigration is being deleted")
		return ctrl.Result{}, nil
	}

	if isNnfProjectGroup(svm.Spec.Resource.Group) {
		// log.V(3).Info("resource group is mine")
	} else {
		// log.V(3).Info("resource group is not mine")
		return ctrl.Result{}, nil
	}
	if !migrationpkg.HasCondition(svm, migrationv1alpha1.MigrationSucceeded) {
		log.Info("Migration not yet complete")
		return ctrl.Result{}, nil
	}
	log.Info("Examining migration state", "migration", svm.Name)

	result := r.validateStorageStateResource(ctx, log, svm)
	if result != nil {
		return *result, nil
	}

	result, crd := r.findCRD(ctx, log, svm)
	if result != nil {
		return *result, nil
	}
	log.V(2).Info("CRD status", "crd", crd.Name, "storedVersions", crd.Status.StoredVersions)

	apiStorageVersion := r.getStorageVersionFromCRD(crd)
	if apiStorageVersion == "" {
		// How does the API server allow this? Doubtful.
		log.Info("unable to find API storage version", "crd", crd.Name)
		return ctrl.Result{}, nil
	}

	// Verify that the storage-version-migrator's state shows it already migrated
	// the resources to the API storage version.
	if apiStorageVersion != svm.Spec.Resource.Version {
		log.Info("storage-version-migrator has not migrated the resources to the API storage version", "crd", crd.Name, "storage-version", apiStorageVersion)
		// We'll be back after the next run of storage-version-migrator.
		return ctrl.Result{}, nil
	}

	// Verify that the API storage version is in the CRD's storedVersions list.
	if !slices.Contains(crd.Status.StoredVersions, apiStorageVersion) {
		// The StorageVersionMigration resource above indicated that this is already
		// done. Maybe we found a race in storage-version-migrator?
		log.Info("API storage version not found in storedVersions list", "crd", crd.Name, "storage-version", apiStorageVersion)
		// We'll be back after the next run of storage-version-migrator.
		return ctrl.Result{}, nil
	}
	log.V(2).Info("API storage version found in storedVersions list", "crd", crd.Name, "storage-version", apiStorageVersion)

	// Trim the storedVersions list.
	// The checks we've performed on the StorageVersionMigration, StorageState,
	// and CRD indicate that all resources for this CRD have been migrated.
	// We can safely remove the old versions from the storedVersions list.
	crd.Status.StoredVersions = append([]string(nil), apiStorageVersion)
	if err := r.Status().Update(ctx, crd); err != nil {
		log.Error(err, "unable to update CustomResourceDefinition status", "crd", crd.Name)
		return ctrl.Result{}, err
	}
	log.Info("CRD status updated", "crd", crd.Name, "storedVersions", crd.Status.StoredVersions)

	return ctrl.Result{}, nil
}

func isNnfProjectGroup(group string) bool {
	switch group {
	case "nnf.cray.hpe.com", "lus.cray.hpe.com", "dataworkflowservices.github.io":
		return true
	}
	return false
}

func (r *StorageVersionMigrationReconciler) getStorageVersionFromCRD(crd *apiextensionsv1.CustomResourceDefinition) string {
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Storage {
			return crd.Spec.Versions[i].Name
		}
	}
	return ""
}

func (r *StorageVersionMigrationReconciler) findCRD(ctx context.Context, inLog logr.Logger, svm *migrationv1alpha1.StorageVersionMigration) (*ctrl.Result, *apiextensionsv1.CustomResourceDefinition) {
	crdName := svm.Spec.Resource.Resource + "." + svm.Spec.Resource.Group
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := r.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
		if apierrors.IsNotFound(err) {
			inLog.V(3).Info("CustomResourceDefinition not found", "crd", crdName)
			// We'll be back after the next run of storage-version-migrator.
			return &ctrl.Result{}, nil
		}
		inLog.Error(err, "unable to fetch CustomResourceDefinition", "crd", crdName)
		return &ctrl.Result{}, nil
	}

	log := inLog.WithValues("crd", crd.Name)
	// Check if the object is being deleted
	if !crd.DeletionTimestamp.IsZero() {
		log.V(3).Info("CustomResourceDefinition is being deleted")
		return &ctrl.Result{}, nil
	}

	if len(crd.Status.StoredVersions) == 0 {
		// We'll be back after the next run of storage-version-migrator.
		log.V(2).Info("no stored versions")
		return &ctrl.Result{}, nil
	}
	if len(crd.Status.StoredVersions) == 1 {
		// If there's only one, then there's nothing for us to do.
		log.V(2).Info("only one stored version", "storedVersions", crd.Status.StoredVersions)
		return &ctrl.Result{}, nil
	}
	if len(crd.Spec.Versions) == 0 {
		// How does the API server allow this? Doubtful.
		log.V(2).Info("no API versions")
		return &ctrl.Result{}, nil
	}
	if len(crd.Spec.Versions) == 1 {
		// If there's only one version, then there's nothing for us to do.
		log.V(2).Info("only one API version", "version", crd.Spec.Versions[0].Name)
		return &ctrl.Result{}, nil
	}

	return nil, crd
}

func (r *StorageVersionMigrationReconciler) validateStorageStateResource(ctx context.Context, inLog logr.Logger, svm *migrationv1alpha1.StorageVersionMigration) *ctrl.Result {
	stgName := svm.Spec.Resource.Resource + "." + svm.Spec.Resource.Group
	storageState := &migrationv1alpha1.StorageState{}
	if err := r.Get(ctx, client.ObjectKey{Name: stgName}, storageState); err != nil {
		if apierrors.IsNotFound(err) {
			inLog.V(3).Info("StorageState not found", "storageState", stgName)
			// We'll be back after the next run of storage-version-migrator.
			return &ctrl.Result{}
		}
		inLog.Error(err, "unable to fetch StorageState", "storageState", stgName)
		return &ctrl.Result{}
	}

	log := inLog.WithValues("storageState", storageState.Name)
	// Check if the object is being deleted
	if !storageState.DeletionTimestamp.IsZero() {
		log.V(3).Info("StorageState is being deleted")
		return &ctrl.Result{}
	}

	if storageState.Status.CurrentStorageVersionHash == "" {
		log.V(2).Info("no current storage version hash")
		return &ctrl.Result{}
	}
	if len(storageState.Status.PersistedStorageVersionHashes) == 0 {
		log.V(2).Info("no persisted storage version hashes")
		return &ctrl.Result{}
	}
	if len(storageState.Status.PersistedStorageVersionHashes) > 1 {
		log.V(2).Info("more than one persisted storage version hash")
		return &ctrl.Result{}
	}
	if storageState.Status.PersistedStorageVersionHashes[0] == "Uknown" {
		log.V(2).Info("unknown persisted storage version hash")
		return &ctrl.Result{}
	}
	if storageState.Status.PersistedStorageVersionHashes[0] != storageState.Status.CurrentStorageVersionHash {
		log.V(2).Info("stale persisted storage version hash")
		return &ctrl.Result{}
	}

	log.V(2).Info("valid persisted storage version hash")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *StorageVersionMigrationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Setup to watch the StorageState resources.
	storageStateMapFunc := func(ctx context.Context, obj client.Object) []reconcile.Request {
		log := logf.Log.WithName("storage-state").WithValues("name", obj.GetName())

		storageState := obj.(*migrationv1alpha1.StorageState)
		if !isNnfProjectGroup(storageState.Spec.Resource.Group) {
			return nil
		}
		log.V(3).Info("StorageState watch triggered")

		// Iterate over the StorageVersionMigration resources and find one that
		// has the StorageState resource's name as a prefix.
		svmList := &migrationv1alpha1.StorageVersionMigrationList{}
		if err := r.List(ctx, svmList); err != nil {
			log.Error(err, "unable to list StorageVersionMigration resources")
			return nil
		}
		for _, svm := range svmList.Items {
			if strings.HasPrefix(svm.Name, storageState.Name+"-") {
				log.Info("StorageVersionMigration resource found", "name", svm.Name)
				return []reconcile.Request{
					{
						NamespacedName: client.ObjectKey{
							Name:      svm.Name,
							Namespace: svm.Namespace,
						},
					},
				}
			}
		}
		log.Info("StorageVersionMigration resource not found")
		return nil
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&migrationv1alpha1.StorageVersionMigration{}).
		Watches(&migrationv1alpha1.StorageState{}, handler.EnqueueRequestsFromMapFunc(storageStateMapFunc)).
		Named("storage_version_maint").
		Complete(r)
}
