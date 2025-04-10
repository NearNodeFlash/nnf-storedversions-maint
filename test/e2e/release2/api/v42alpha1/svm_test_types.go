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

package v42alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SvmTestSpec defines the desired state of SvmTest
type SvmTestSpec struct {
	// DesiredState is the desired state
	DesiredState string `json:"desiredState"`
}

// SvmTestStatus defines the observed state of SvmTest
type SvmTestStatus struct {
	// ObservedState is the observed state
	ObservedState string `json:"observedState"`
}

// SvmTest is the Schema for the svmtests API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type SvmTest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SvmTestSpec   `json:"spec,omitempty"`
	Status SvmTestStatus `json:"status,omitempty"`
}

// SvmTestList contains a list of SvmTest
// +kubebuilder:object:root=true
type SvmTestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SvmTest `json:"items"`
}
