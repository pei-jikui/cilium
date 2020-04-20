// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchers

import (
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/endpointmanager/idallocator"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) nodesInit(k8sClient kubernetes.Interface) {
	_, nodeController := informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.ParseSelectorOrDie("metadata.name="+node.GetName())),
		&v1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				if oldNode := k8s.ObjToV1Node(oldObj); oldNode != nil {
					valid = true
					if newNode := k8s.ObjToV1Node(newObj); newNode != nil {
						if k8s.EqualV1NodeByLabels(oldNode, newNode) {
							equal = true
						} else {
							err := k.updateK8sNodeV1(oldNode, newNode)
							k.K8sEventProcessed(metricNode, metricUpdate, err == nil)
						}
					}
				}
				k.K8sEventReceived(metricNode, metricUpdate, valid, equal)
			},
		},
		k8s.ConvertToNode,
	)

	k.blockWaitGroupToSyncResources(wait.NeverStop, nil, nodeController, k8sAPIGroupNodeV1Core)
	go nodeController.Run(wait.NeverStop)
	k.k8sAPIGroups.addAPI(k8sAPIGroupNodeV1Core)
}

func (k *K8sWatcher) updateK8sNodeV1(oldK8sNode, newK8sNode *types.Node) error {
	// Check label updates.
	oldNodeLabels := oldK8sNode.GetLabels()
	newNodeLabels := newK8sNode.GetLabels()
	labelsChanged := !comparator.MapStringEquals(oldNodeLabels, newNodeLabels)

	// Labels didn't change.
	if !labelsChanged {
		return nil
	}

	nodeEP := k.endpointManager.LookupCiliumID(idallocator.HostEndpointID)
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return nil
	}

	err := updateEndpointLabels(nodeEP, oldNodeLabels, newNodeLabels)
	if err != nil {
		return err
	}
	return nil
}
