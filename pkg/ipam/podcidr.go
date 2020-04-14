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

package ipam

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/trigger"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
)

type allocatorType string

const (
	v4AllocatorType = "IPv4"
	v6AllocatorType = "IPv6"
)

// ErrAllocatorNotFound is an error that should be used in case the node tries
// to allocate a CIDR for an allocator that does not exist.
type ErrAllocatorNotFound struct {
	cidr          *net.IPNet
	allocatorType allocatorType
}

// Error returns the human-readable error for the ErrAllocatorNotFound
func (e *ErrAllocatorNotFound) Error() string {
	return fmt.Sprintf("unable to allocate CIDR %s since allocator for %s addresses does not exist", e.cidr, e.allocatorType)
}

// ErrConflictIPNet is an error that should be used when 2 CIDRs colide when
// the node has 2 or more podCIDRs for the same IP family.
type ErrConflictIPNet struct {
	newIPNet      *net.IPNet
	existingIPNet *net.IPNet
}

// Error returns the human-readable error for the ErrConflictIPNet
func (e *ErrConflictIPNet) Error() string {
	return fmt.Sprintf("IPNet %s conflicts with %s as they are from the same IP family type", e.newIPNet, e.existingIPNet)
}

// ErrCIDRAllocated is an error that should be used when the requested CIDR
// is already allocated.
type ErrCIDRAllocated struct {
	cidr *net.IPNet
}

// Error returns the human-readable error for the ErrAllocatorNotFound
func (e *ErrCIDRAllocated) Error() string {
	return fmt.Sprintf("requested CIDR (%s) is already allocated", e.cidr)
}

// parsePodCIDRs will return the v4 and v6 CIDRs found in the podCIDRs.
// Returns an error in case multiple CIDRs exist for the same IP family.
func parsePodCIDRs(podCIDRs []string) (*net.IPNet, *net.IPNet, error) {
	var v4IPNet, v6IPNet *net.IPNet
	for _, podCIDR := range podCIDRs {
		ip, ipNet, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return nil, nil, err
		}
		if ipPkg.IsIPv4(ip) {
			if v4IPNet != nil {
				return nil, nil, &ErrConflictIPNet{
					newIPNet:      ipNet,
					existingIPNet: v4IPNet,
				}
			}
			v4IPNet = ipNet
		} else {
			if v6IPNet != nil {
				return nil, nil, &ErrConflictIPNet{
					newIPNet:      ipNet,
					existingIPNet: v6IPNet,
				}
			}
			v6IPNet = ipNet
		}
	}
	return v4IPNet, v6IPNet, nil
}

// nodeCIDRs is a wrapper that contains all the podCIDRs a node can have.
type nodeCIDRs struct {
	v4PodCIDR, v6PodCIDR *net.IPNet
}

type k8sOp int

const (
	k8sOpCreate k8sOp = iota
	k8sOpDelete
	k8sOpUpdate
	k8sOpUpdateStatus
)

// ciliumNodeK8sOp is a wrapper with the operation that should be performed
// in kubernetes.
type ciliumNodeK8sOp struct {
	ciliumNode *v2.CiliumNode
	op         k8sOp
}

var (
	updateK8sInterval = 15 * time.Second
)

// NodesPodCIDRManager will be used to manage podCIDRs for the nodes in the
// cluster.
type NodesPodCIDRManager struct {
	k8sReSyncController *controller.Manager
	k8sReSync           *trigger.Trigger

	// Lock protects all fields below
	lock.Mutex
	// v4PodCIDR contains the CIDRs for IPv4 addresses
	v4ClusterCIDR CIDRAllocator
	// v4PodCIDR contains the CIDRs for IPv6 addresses
	v6ClusterCIDR CIDRAllocator
	// nodes maps a node name to the CIDRs allocated for that node
	nodes map[string]*nodeCIDRs
	// maps a node name to the operation that needs to be performed in
	// kubernetes.
	ciliumNodesToK8s map[string]*ciliumNodeK8sOp
}

type CIDRAllocator interface {
	Occupy(cidr *net.IPNet) error
	AllocateNext() (*net.IPNet, error)
	Release(cidr *net.IPNet) error
	IsAllocated(cidr *net.IPNet) (bool, error)
}

// NewNodesPodCIDRManager will create a node podCIDR manager.
// Both v4CIDR and v6CIDR can be nil, but not at the same time.
// nodeGetter will be used to populate synced node status / spec with
// kubernetes.
func NewNodesPodCIDRManager(v4CIDR, v6CIDR CIDRAllocator, nodeGetter CiliumNodeGetterUpdater, triggerMetrics trigger.MetricsObserver) *NodesPodCIDRManager {
	n := &NodesPodCIDRManager{
		v4ClusterCIDR:       v4CIDR,
		v6ClusterCIDR:       v6CIDR,
		nodes:               map[string]*nodeCIDRs{},
		ciliumNodesToK8s:    map[string]*ciliumNodeK8sOp{},
		k8sReSyncController: controller.NewManager(),
	}

	// Have a trigger so that multiple calls, within a second, to sync with k8s
	// will result as it was a single call being made.
	t, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Second,
		TriggerFunc: func([]string) {
			// Trigger execute UpdateController multiple times so that we
			// keep retrying the sync against k8s in case of failure.
			n.k8sReSyncController.UpdateController("update-cilium-nodes-pod-cidr",
				controller.ControllerParams{
					DoFunc: func(context.Context) error {
						n.Mutex.Lock()
						defer n.Mutex.Unlock()
						return syncToK8s(nodeGetter, n.ciliumNodesToK8s)
					},
					RunInterval: updateK8sInterval,
				},
			)
		},
		MetricsObserver: triggerMetrics,
		Name:            "update-cilium-nodes-pod-cidr",
	})
	if err != nil {
		// None of the parameters set in the NewTrigger are from the user so we
		// can panic here.
		panic(err)
	}

	n.k8sReSync = t

	return n
}

// syncToK8s will sync all nodes present in the ciliumNodesToK8s into kubernetes
// In case any of the nodes failed to be synced with kubernetes the returned
// error is for one of those nodes. Remaining nodes will still be synced with
// kubernetes.
func syncToK8s(nodeGetter CiliumNodeGetterUpdater, ciliumNodesToK8s map[string]*ciliumNodeK8sOp) (retErr error) {
	for nodeName, nodeToK8s := range ciliumNodesToK8s {
		var err error
		switch nodeToK8s.op {
		case k8sOpCreate:
			// Try creating the node
			_, err = nodeGetter.Create(nodeToK8s.ciliumNode)
			switch {
			// There was a conflict so this function will return an error
			// and we will fetch the latest version of the cilium node
			// so the next time we will need to perform an update.
			case k8sErrors.IsConflict(err) || k8sErrors.IsAlreadyExists(err):
				// the err in the line below is not being shadowed accidentally
				// the caller of the syncToK8s function should not care about the
				// these errors.
				newCiliumNode, err := nodeGetter.Get(nodeToK8s.ciliumNode.GetName())
				// We only perform an update if we were able to successfully
				// retrieve the node. The operator is listening for cilium node
				// events. In case the node was deleted, which could be a reason
				// for why the Get returned an error, the operator will then
				// remove the cilium node from the allocated nodes in the pool.
				if err == nil {
					nodeToK8s.op = k8sOpUpdate
					newCiliumNode.Spec.IPAM.PodCIDRs = nodeToK8s.ciliumNode.Spec.IPAM.PodCIDRs
					if len(newCiliumNode.OwnerReferences) == 0 {
						newCiliumNode.OwnerReferences = nodeToK8s.ciliumNode.GetOwnerReferences()
					}
					nodeToK8s.ciliumNode = newCiliumNode
					ciliumNodesToK8s[nodeName] = nodeToK8s
				}
			}
		case k8sOpUpdate:
			_, err = nodeGetter.Update(nil, nodeToK8s.ciliumNode)
			switch {
			case k8sErrors.IsNotFound(err):
				// In case the node was not found we should not try to re-create
				// it because the operator will receive the delete node event
				// from k8s and will be eventually deleted from the list of
				// nodes that need to be re-synced with k8s.
				err = nil
			case k8sErrors.IsConflict(err):
				// the err in the line below is not being shadowed accidentally
				// we caller of this function should not care about the
				// these errors.
				newCiliumNode, err := nodeGetter.Get(nodeToK8s.ciliumNode.GetName())
				if err == nil {
					newCiliumNode.Spec.IPAM.PodCIDRs = nodeToK8s.ciliumNode.Spec.IPAM.PodCIDRs
					if len(newCiliumNode.OwnerReferences) == 0 {
						newCiliumNode.OwnerReferences = nodeToK8s.ciliumNode.GetOwnerReferences()
					}
					nodeToK8s.ciliumNode = newCiliumNode
					ciliumNodesToK8s[nodeName] = nodeToK8s
				}
			}
		case k8sOpUpdateStatus:
			_, err = nodeGetter.UpdateStatus(nil, nodeToK8s.ciliumNode)
			switch {
			case k8sErrors.IsNotFound(err):
				// In case the node was not found we should not try to re-create
				// it because the operator will receive the delete node event
				// from k8s and will be eventually deleted from the list of
				// nodes that need to be re-synced with k8s.
				err = nil
			case k8sErrors.IsConflict(err):
				// the err in the line below is not being shadowed accidentally
				// we caller of this function should not care about the
				// these errors.
				newCiliumNode, err := nodeGetter.Get(nodeToK8s.ciliumNode.GetName())
				if err == nil {
					newCiliumNode.Spec.IPAM.PodCIDRs = nodeToK8s.ciliumNode.Spec.IPAM.PodCIDRs
					if len(newCiliumNode.OwnerReferences) == 0 {
						newCiliumNode.OwnerReferences = nodeToK8s.ciliumNode.GetOwnerReferences()
					}
					newCiliumNode.Status.IPAM.OperatorStatus.Error = nodeToK8s.ciliumNode.Status.IPAM.OperatorStatus.Error
					nodeToK8s.ciliumNode = newCiliumNode
					ciliumNodesToK8s[nodeName] = nodeToK8s
				}
			}
		case k8sOpDelete:
			err = nodeGetter.Delete(nodeName)
			if k8sErrors.IsNotFound(err) || k8sErrors.IsGone(err) {
				err = nil
			}
		}
		if err == nil {
			delete(ciliumNodesToK8s, nodeName)
		} else {
			retErr = err
		}
	}
	return
}

// Create will re-allocate the node podCIDRs. In case the node already has
// podCIDRs allocated, the podCIDR allocator will try to allocate those CIDRs.
// In case the CIDRs were able to be allocated the CiliumNode will have its
// podCIDRs fields set with the allocated CIDRs.
// In case the CIDRs were unable to be allocated this function will return
// false and the node will have its status updated into kubernetes with the
// error message.
func (n *NodesPodCIDRManager) Create(node *v2.CiliumNode) bool {
	cn, updateStatus, err := n.AllocateNode(node)
	if err != nil {
		return false
	}
	if updateStatus {
		// the n.syncNode will never fail because it's only adding elements to a map.
		// This will later on sync the node into k8s by the controller defined
		// NodesPodCIDRManager's controller, which keeps retrying to create the
		// node in k8s until it succeeds.

		// If the resource version is != "" it means the object already exists
		// in kubernetes so we should perform an update status instead of a create.
		if cn.GetResourceVersion() != "" {
			n.syncNode(k8sOpUpdateStatus, cn)
		}
		n.syncNode(k8sOpCreate, cn)
		return false
	}
	if cn == nil {
		// no-op
		return true
	}
	// If the resource version is != "" it means the object already exists
	// in kubernetes so we should perform an update instead of a create.
	if cn.GetResourceVersion() != "" {
		n.syncNode(k8sOpUpdate, cn)
		return true
	}
	n.syncNode(k8sOpCreate, cn)
	return true
}

// Update will re-allocate the node podCIDRs. In case the node already has
// podCIDRs allocated, the podCIDR allocator will try to allocate those CIDRs.
// In case the CIDRs were able to be allocated the CiliumNode will have its
// podCIDRs fields set with the allocated CIDRs.
// In case the CIDRs were unable to be allocated this function will return
// false and the node will have its status updated into kubernetes with the
// error message.
func (n *NodesPodCIDRManager) Update(node *v2.CiliumNode) bool {
	cn, updateStatus, err := n.AllocateNode(node)
	if err != nil {
		return false
	}
	if updateStatus {
		// the n.syncNode will never fail because it's only adding elements to a map.
		// This will later on sync the node into k8s by the controller defined
		// NodesPodCIDRManager's controller, which keeps retrying to update the
		// node status in k8s until it succeeds.
		n.syncNode(k8sOpUpdateStatus, cn)
		return false
	}
	if cn == nil {
		// no-op
		return true
	}
	// the n.syncNode will never fail because it's only adding elements to a map.
	// This will later on sync the node into k8s by the controller defined
	// NodesPodCIDRManager's controller, which keeps retrying to update the
	// node in k8s until it succeeds.
	n.syncNode(k8sOpUpdate, cn)
	return true
}

// Delete deletes the node from the allocator and releases the associated
// CIDRs of that node.
func (n *NodesPodCIDRManager) Delete(nodeName string) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	found := n.releaseIPNets(nodeName)
	if !found {
		return
	}
	// Mark the node to be deleted in k8s.
	n.ciliumNodesToK8s[nodeName] = &ciliumNodeK8sOp{
		op: k8sOpDelete,
	}
	n.k8sReSync.Trigger()
	return
}

// Resync resyncs the nodes with k8s.
func (n *NodesPodCIDRManager) Resync(context.Context, time.Time) {
	n.k8sReSync.Trigger()
}

// AllocateNode allocates the podCIDRs for the given node. Returns a DeepCopied
// node with the podCIDRs allocated. In case there wasn't CIDRs allocated
// the returned node will be nil.
// If updateStatus returns true, it means an update of CiliumNode Status should
// be performed into kubernetes.
func (n *NodesPodCIDRManager) AllocateNode(node *v2.CiliumNode) (cn *v2.CiliumNode, updateStatus bool, err error) {
	var (
		v4CIDR, v6CIDR *net.IPNet
		allocated      bool
	)

	defer func() {
		// Overwrite err value if we want to update the status of the
		// cilium node into kubernetes.
		if err != nil && updateStatus {
			cn = node.DeepCopy()
			cn.Status.IPAM.OperatorStatus.Error = err.Error()
			err = nil
		}
	}()

	if len(node.Spec.IPAM.PodCIDRs) == 0 {
		n.Mutex.Lock()
		defer n.Mutex.Unlock()
		// Allocate the next free CIDRs
		v4CIDR, v6CIDR, _, err = n.allocateNext(node.GetName())
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
	} else {
		v4CIDR, v6CIDR, err = parsePodCIDRs(node.Spec.IPAM.PodCIDRs)
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
		n.Mutex.Lock()
		defer n.Mutex.Unlock()
		// Try to allocate the podCIDRs in the node, if there was a need
		// for new CIDRs to be allocated the allocated returned value will be
		// set to true.
		allocated, err = n.allocateIPNets(node.Name, v4CIDR, v6CIDR)
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
		if !allocated {
			// no-op
			return nil, false, nil
		}
	}

	cn = node.DeepCopy()

	if v4CIDR != nil {
		cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v4CIDR.String())
	}
	if v6CIDR != nil {
		cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v6CIDR.String())
	}
	return cn, false, nil
}

// syncNode adds the given node to the map of nodes that need to be synchronized
// with kubernetes and triggers a new resync.
func (n *NodesPodCIDRManager) syncNode(op k8sOp, ciliumNode *v2.CiliumNode) {
	n.ciliumNodesToK8s[ciliumNode.GetName()] = &ciliumNodeK8sOp{
		ciliumNode: ciliumNode,
		op:         op,
	}
	n.k8sReSync.Trigger()
}

// releaseIPNets release the CIDRs allocated for this node.
// Returns true if the node was found in the allocator, false otherwise.
func (n *NodesPodCIDRManager) releaseIPNets(nodeName string) bool {
	ipNets, ok := n.nodes[nodeName]
	if !ok {
		return false
	}

	delete(n.nodes, nodeName)

	if ipNets.v4PodCIDR != nil && !reflect.ValueOf(n.v4ClusterCIDR).IsNil() {
		n.v4ClusterCIDR.Release(ipNets.v4PodCIDR)
	}
	if ipNets.v6PodCIDR != nil && !reflect.ValueOf(n.v6ClusterCIDR).IsNil() {
		n.v6ClusterCIDR.Release(ipNets.v6PodCIDR)
	}
	return true
}

// allocateIPNets allows the node to allocate new CIDRs. If the node had CIDRs
// previously allocated by this allocator the old CIDRs will be released and
// new ones will be allocated.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated.
// In case an error is returned no CIDRs were allocated nor released.
func (n *NodesPodCIDRManager) allocateIPNets(nodeName string, v4CIDR, v6CIDR *net.IPNet) (allocated bool, err error) {
	// If this node had already allocated CIDRs then release the previous
	// allocated CIDRs and return new ones.
	var keepV4CIDR, keepV6CIDR bool
	oldNodeCIDRs, nodeHasCIDRs := n.nodes[nodeName]
	if nodeHasCIDRs {
		// If the requested CIDRs are the same as already previously allocated
		// for this node then don't do any operation.
		keepV4CIDR = cidr.Equal(oldNodeCIDRs.v4PodCIDR, v4CIDR)
		keepV6CIDR = cidr.Equal(oldNodeCIDRs.v6PodCIDR, v6CIDR)
		if keepV4CIDR && keepV6CIDR {
			return
		}
	}

	var (
		revertStack revert.RevertStack
		revertFunc  revert.RevertFunc
	)

	defer func() {
		// Revert any operation made so far in case any of them failed.
		if err != nil {
			revertStack.Revert()
		}
	}()

	if !keepV4CIDR {
		if nodeHasCIDRs {
			revertFunc, err = allocateIPNet(v4AllocatorType, n.v4ClusterCIDR, oldNodeCIDRs.v4PodCIDR, v4CIDR)
		} else {
			revertFunc, err = allocateIPNet(v4AllocatorType, n.v4ClusterCIDR, nil, v4CIDR)
		}
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
	}
	if !keepV6CIDR {
		if nodeHasCIDRs {
			revertFunc, err = allocateIPNet(v6AllocatorType, n.v6ClusterCIDR, oldNodeCIDRs.v6PodCIDR, v6CIDR)
		} else {
			revertFunc, err = allocateIPNet(v6AllocatorType, n.v6ClusterCIDR, nil, v6CIDR)
		}
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
	}

	// Only add the node to the list of nodes allocated if there wasn't
	// an error allocating the CIDR
	n.nodes[nodeName] = &nodeCIDRs{
		v4PodCIDR: v4CIDR,
		v6PodCIDR: v6CIDR,
	}

	return true, nil
}

// allocateIPNet allocates the `newCidr` in the cidrSet allocator. If the
// the `newCIDR` is already allocated and error is returned.
// In case the function returns successfully, it's up to the caller to execute
// the revert function provided to revert all state made. If the function
// returns an error the caller of this function can assume no state was
// modified.
func allocateIPNet(allType allocatorType, cidrSet CIDRAllocator, oldCidr, newCidr *net.IPNet) (revertFunc revert.RevertFunc, err error) {
	// If the node does not need a new CIDR then this will be a no-op
	// which means the node might keep the old CIDR previously allocated,
	// if any.
	if newCidr == nil {
		return
	}

	var revertStack revert.RevertStack
	defer func() {
		if err != nil {
			// In case of an error revert all operations made up to this point
			revertStack.Revert()
		}
	}()

	if reflect.ValueOf(cidrSet).IsNil() {
		// Return an error if the node tries to allocate a CIDR and
		// we don't have a CIDR set for this CIDR type.
		return nil, &ErrAllocatorNotFound{
			cidr:          newCidr,
			allocatorType: allType,
		}
	}

	if oldCidr != nil {
		// Release the old CIDR
		err = cidrSet.Release(oldCidr)
		if err != nil {
			return
		}
		revertStack.Push(func() error {
			// In case of an error re-occupy the old cidr
			return cidrSet.Occupy(oldCidr)
		})
	}
	// Check if the CIDR is already allocated before allocating it.
	var isAllocated bool
	isAllocated, err = cidrSet.IsAllocated(newCidr)
	if err != nil {
		return
	}
	if isAllocated {
		return nil, &ErrCIDRAllocated{
			cidr: newCidr,
		}
	}

	// Try to occupy allocate this new CIDR
	err = cidrSet.Occupy(newCidr)
	if err != nil {
		return
	}

	revertStack.Push(func() error {
		// In case of a follow up error release this new allocated CIDR.
		return cidrSet.Release(newCidr)
	})
	return revertStack.Revert, nil
}

// allocateNext returns the next v4 and / or v6 CIDR available in the CIDR
// allocator. The CIDRs are only allocated if the respective CIDR allocators
// are available. If the node had a CIDR previously allocated the same CIDR
// allocated to that node is returned.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated, for example in the case the node had already allocated CIDRs.
// In case an error is returned no CIDRs were allocated.
func (n *NodesPodCIDRManager) allocateNext(nodeName string) (v4CIDR, v6CIDR *net.IPNet, allocated bool, err error) {
	// If this node had already allocated CIDRs then returned the already
	// allocated CIDRs
	if nodeCIDRs, ok := n.nodes[nodeName]; ok {
		v4CIDR = nodeCIDRs.v4PodCIDR
		v6CIDR = nodeCIDRs.v6PodCIDR
		return
	}

	// Only allocate a v4 CIDR if the v4CIDR allocator is available
	if !reflect.ValueOf(n.v4ClusterCIDR).IsNil() {
		v4CIDR, err = n.v4ClusterCIDR.AllocateNext()
		if err != nil {
			return
		}
		defer func() {
			// In case of an error revert the v4 allocated address
			if err != nil {
				n.v4ClusterCIDR.Release(v4CIDR)
				v4CIDR = nil
			}
		}()
	}

	// Only allocate a v6 CIDR if the v4CIDR allocator is available
	if !reflect.ValueOf(n.v6ClusterCIDR).IsNil() {
		v6CIDR, err = n.v6ClusterCIDR.AllocateNext()
		if err != nil {
			return
		}
		defer func() {
			// In case of an error revert the v6 allocated address
			if err != nil {
				n.v6ClusterCIDR.Release(v6CIDR)
				v6CIDR = nil
			}
		}()
	}

	n.nodes[nodeName] = &nodeCIDRs{
		v4PodCIDR: v4CIDR,
		v6PodCIDR: v6CIDR,
	}

	return v4CIDR, v6CIDR, true, nil

}
