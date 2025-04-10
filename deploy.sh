#!/bin/bash

# Copyright 2021-2025 Hewlett Packard Enterprise Development LP
# Other additional copyright holders may be indicated within.
#
# The entirety of this work is licensed under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
#
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Deploy controller to the K8s cluster specified in ~/.kube/config.

set -e
set -o pipefail

usage() {
    cat <<EOF
Deploy or Undeploy
Usage $0 COMMAND KUSTOMIZE <OVERLAY_DIR>

Commands:
    deploy              Deploy data movement
    undeploy            Undeploy data movement
EOF
}

CMD=$1
KUSTOMIZE=$2
OVERLAY_DIR=$3

case $CMD in
deploy)
    $KUSTOMIZE build "$OVERLAY_DIR" | kubectl apply -f - || true
    ;;
undeploy)
    # Do not touch the namespace resource when deleting this service.
    # Wishing for yq(1)...
    $KUSTOMIZE build "$OVERLAY_DIR" | python3 -c 'import yaml, sys; all_docs = yaml.safe_load_all(sys.stdin); less_docs=[doc for doc in all_docs if doc["kind"] != "Namespace"]; print(yaml.dump_all(less_docs))' |  kubectl delete --ignore-not-found -f -
    ;;
*)
    usage
    exit 1
    ;;
esac
