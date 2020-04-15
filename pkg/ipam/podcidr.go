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
	"errors"
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
	cidr          []*net.IPNet
	allocatorType allocatorType
}

// Error returns the human-readable error for the ErrAllocatorNotFound
func (e *ErrAllocatorNotFound) Error() string {
	return fmt.Sprintf("unable to allocate CIDR %s since allocator for %s addresses does not exist", e.cidr, e.allocatorType)
}

// ErrAllocatorFull ...
type ErrAllocatorFull struct {
}

// Error returns the human-readable error for the ErrAllocatorFull
func (e *ErrAllocatorFull) Error() string {
	return fmt.Sprintf("allocator full")
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
// Returns an error in case one of the CIDRs are not valid.
func parsePodCIDRs(podCIDRs []string) (*nodeCIDRs, error) {
	var cidrs nodeCIDRs
	for _, podCIDR := range podCIDRs {
		ip, ipNet, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return nil, err
		}
		if ipPkg.IsIPv4(ip) {
			cidrs.v4PodCIDR = append(cidrs.v4PodCIDR, ipNet)
		} else {
			cidrs.v6PodCIDR = append(cidrs.v6PodCIDR, ipNet)
		}
	}
	return &cidrs, nil
}

// nodeCIDRs is a wrapper that contains all the podCIDRs a node can have.
type nodeCIDRs struct {
	v4PodCIDR, v6PodCIDR []*net.IPNet
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
	// v4ClusterCIDRs contains the CIDRs for IPv4 addresses
	v4ClusterCIDRs []CIDRAllocator
	// v6ClusterCIDRs contains the CIDRs for IPv6 addresses
	v6ClusterCIDRs []CIDRAllocator
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
	IsIPv6() bool
	IsFree() bool
}

// NewNodesPodCIDRManager will create a node podCIDR manager.
// Both v4Allocators and v6Allocators can be nil, but not at the same time.
// nodeGetter will be used to populate synced node status / spec with
// kubernetes.
func NewNodesPodCIDRManager(v4Allocators, v6Allocators []CIDRAllocator, nodeGetter CiliumNodeGetterUpdater, triggerMetrics trigger.MetricsObserver) *NodesPodCIDRManager {
	n := &NodesPodCIDRManager{
		v4ClusterCIDRs:      v4Allocators,
		v6ClusterCIDRs:      v6Allocators,
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
				// the caller of this function should not care about conflict
				// errors.
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
				// the caller of this function should not care about conflict
				// errors.
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
// In case the CIDRs were able to be allocated, the CiliumNode will have its
// podCIDRs fields set with the allocated CIDRs.
// In case the CIDRs were unable to be allocated, this function will return
// false and the node will have its status updated into kubernetes with the
// error message by the NodesPodCIDRManager.
func (n *NodesPodCIDRManager) Create(node *v2.CiliumNode) bool {
	cn, allocated, err := n.AllocateNode(node)
	if err != nil {
		return false
	}
	// if allocated is false it means that we were unable to allocate
	// a CIDR so we need to update the status of the node into k8s.
	if !allocated && cn != nil {
		// the n.syncNode will never fail because it's only adding elements to a
		// map.
		// NodesPodCIDRManager will later on sync the node into k8s by the
		// controller defined, which keeps retrying to create the node in k8s
		// until it succeeds.

		// If the resource version is != "" it means the object already exists
		// in kubernetes so we should perform an update status instead of a create.
		if cn.GetResourceVersion() != "" {
			n.syncNode(k8sOpUpdateStatus, cn)
		} else {
			n.syncNode(k8sOpCreate, cn)
		}
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
	} else {
		n.syncNode(k8sOpCreate, cn)
	}
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
	cn, allocated, err := n.AllocateNode(node)
	if err != nil {
		return false
	}
	// if allocated is false it means that we were unable to allocate
	// a CIDR so we need to update the status of the node into k8s.
	if !allocated && cn != nil {
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
// node with the podCIDRs allocated. In case there weren't CIDRs allocated
// the returned node will be nil.
// If allocated returns false, it means an update of CiliumNode Status should
// be performed into kubernetes as an error have happened while trying to
// allocate a CIDR for this node.
func (n *NodesPodCIDRManager) AllocateNode(node *v2.CiliumNode) (cn *v2.CiliumNode, allocated bool, err error) {
	var (
		cidrs        *nodeCIDRs
		updateStatus bool
	)

	defer func() {
		// Overwrite err value if we want to update the status of the
		// cilium node into kubernetes.
		if err != nil && updateStatus {
			cn = node.DeepCopy()
			cn.Status.IPAM.OperatorStatus.Error = err.Error()
			err = nil
			allocated = false
		}
	}()

	if len(node.Spec.IPAM.PodCIDRs) == 0 {
		n.Mutex.Lock()
		defer n.Mutex.Unlock()
		// Allocate the next free CIDRs
		cidrs, _, err = n.allocateNext(node.GetName())
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
	} else {
		cidrs, err = parsePodCIDRs(node.Spec.IPAM.PodCIDRs)
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
		allocated, err = n.allocateIPNets(node.Name, cidrs.v4PodCIDR, cidrs.v6PodCIDR)
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

	if cidrs.v4PodCIDR != nil {
		for _, v4CIDR := range cidrs.v4PodCIDR {
			cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v4CIDR.String())
		}
	}
	if cidrs.v6PodCIDR != nil {
		for _, v6CIDR := range cidrs.v6PodCIDR {
			cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v6CIDR.String())
		}
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
	cidrs, ok := n.nodes[nodeName]
	if !ok {
		return false
	}

	delete(n.nodes, nodeName)

	if len(cidrs.v4PodCIDR) != 0 && len(n.v4ClusterCIDRs) != 0 {
		for _, ipNet := range cidrs.v4PodCIDR {
			for _, v4ClusterCIDR := range n.v4ClusterCIDRs {
				v4ClusterCIDR.Release(ipNet)
			}
		}
	}
	if len(cidrs.v6PodCIDR) != 0 && len(n.v6ClusterCIDRs) != 0 {
		for _, ipNet := range cidrs.v6PodCIDR {
			for _, v6ClusterCIDR := range n.v6ClusterCIDRs {
				v6ClusterCIDR.Release(ipNet)
			}
		}
	}
	return true
}

// allocateIPNets allows the node to allocate new CIDRs. If the node had CIDRs
// previously allocated by this allocator the old CIDRs will be released and
// new ones will be allocated.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated.
// In case an error is returned no CIDRs were allocated nor released.
func (n *NodesPodCIDRManager) allocateIPNets(nodeName string, v4CIDR, v6CIDR []*net.IPNet) (allocated bool, err error) {
	// If this node had already allocated CIDRs then release the previous
	// allocated CIDRs and return new ones.
	var keepV4CIDR, keepV6CIDR bool
	oldNodeCIDRs, nodeHasCIDRs := n.nodes[nodeName]
	if nodeHasCIDRs {
		keepV4CIDR = cidr.ContainsAll(oldNodeCIDRs.v4PodCIDR, v4CIDR)
		keepV6CIDR = cidr.ContainsAll(oldNodeCIDRs.v6PodCIDR, v6CIDR)
		if keepV4CIDR && keepV6CIDR {
			return
		} else{
			// We don't support changing podCIDRs of already allocated nodes.
			return false, errors.New("Operation not supported!")
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
			revertFunc, err = allocateIPNet(v4AllocatorType, n.v4ClusterCIDRs, oldNodeCIDRs.v4PodCIDR, v4CIDR)
		} else {
			revertFunc, err = allocateIPNet(v4AllocatorType, n.v4ClusterCIDRs, nil, v4CIDR)
		}
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
	}
	if !keepV6CIDR {
		if nodeHasCIDRs {
			revertFunc, err = allocateIPNet(v6AllocatorType, n.v6ClusterCIDRs, oldNodeCIDRs.v6PodCIDR, v6CIDR)
		} else {
			revertFunc, err = allocateIPNet(v6AllocatorType, n.v6ClusterCIDRs, nil, v6CIDR)
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
// the `newCIDR` is already allocated an error is returned.
// In case the function returns successfully, it's up to the caller to execute
// the revert function provided to revert all state made. If the function
// returns an error the caller of this function can assume no state was
// modified to the given cidrSets.
func allocateIPNet(allType allocatorType, cidrSets []CIDRAllocator, oldCidrs, newCidrs []*net.IPNet) (revertFunc revert.RevertFunc, err error) {
	// If the node does not need a new CIDR then this will be a no-op
	// which means the node might keep the old CIDR previously allocated,
	// if any.
	if newCidrs == nil {
		return
	}

	var revertStack revert.RevertStack
	defer func() {
		if err != nil {
			// In case of an error revert all operations made up to this point
			revertStack.Revert()
		}
	}()

	if len(cidrSets) == 0 {
		// Return an error if the node tries to allocate a CIDR and
		// we don't have a CIDR set for this CIDR type.
		return nil, &ErrAllocatorNotFound{
			cidr:          newCidrs,
			allocatorType: allType,
		}
	}

	if oldCidrs != nil {
		// Release the old CIDRs
		for _, cidrSet := range cidrSets {
			var isAllocated bool
			for _, oldCIDR := range oldCidrs {
				isAllocated, err = cidrSet.IsAllocated(oldCIDR)
				if err != nil {
					// If an error is returned we can assume it is because
					// the oldCIDR does not belong to the given cidrSet
					continue
				}
				if isAllocated {
					err = cidrSet.Release(oldCIDR)
					if err != nil {
						return
					}
					revertStack.Push(func() error {
						// In case of an error re-occupy the old cidr
						return cidrSet.Occupy(oldCIDR)
					})
					break
				}
			}
		}
	}
	// Check if the CIDR is already allocated before allocating it.
	for _, newCIDR := range newCidrs {
		var isAllocated, occupied bool
		for _, cidrSet := range cidrSets {
			isAllocated, err = cidrSet.IsAllocated(newCIDR)
			if err != nil {
				// Ignore this error because we need to find out which
				// allocator can allocate this CIDR.
				continue
			}
			if isAllocated {
				return nil, &ErrCIDRAllocated{
					cidr: newCIDR,
				}
			}
			// Try to allocate this new CIDR
			err = cidrSet.Occupy(newCIDR)
			if err != nil {
				// Ignore this error because we need to find out which
				// allocator can allocate this CIDR.
				continue
			}
			occupied = true
			revertStack.Push(func() error {
				// In case of a follow up error release this new allocated CIDR.
				return cidrSet.Release(newCIDR)
			})
			break
		}
		// If we were unable to occupy the CIDRs on any allocators then return
		// immediately as one of the CIDR allocators should be able to allocate
		// this new CIDR.
		if !occupied {
			return
		}
	}

	return revertStack.Revert, nil
}

// allocateNext returns the next v4 and / or v6 CIDR available in the CIDR
// allocator. The CIDRs are only allocated if the respective CIDR allocators
// are available. If the node had a CIDR previously allocated the same CIDR
// allocated to that node is returned.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated, for example in the case the node had already allocated CIDRs.
// In case an error is returned no CIDRs were allocated.
func (n *NodesPodCIDRManager) allocateNext(nodeName string) (nCIDRs *nodeCIDRs, allocated bool, err error) {
	// If this node had already allocated CIDRs then returned the already
	// allocated CIDRs
	if cidrs, ok := n.nodes[nodeName]; ok {
		nCIDRs = cidrs
		return
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

	var v4CIDR, v6CIDR *net.IPNet

	// Only allocate a v4 CIDR if the v4CIDR allocator is available
	if len(n.v4ClusterCIDRs) != 0 {
		revertFunc, v4CIDR, err = allocateFirstFreeCIDR(n.v4ClusterCIDRs)
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
	}
	if len(n.v6ClusterCIDRs) != 0 {
		revertFunc, v6CIDR, err = allocateFirstFreeCIDR(n.v6ClusterCIDRs)
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
	}

	nCIDRs = &nodeCIDRs{
		v4PodCIDR: []*net.IPNet{v4CIDR},
		v6PodCIDR: []*net.IPNet{v6CIDR},
	}
	n.nodes[nodeName] = nCIDRs

	return nCIDRs, true, nil

}

func allocateFirstFreeCIDR(cidrAllocators []CIDRAllocator) (revertFunc revert.RevertFunc, cidr *net.IPNet, err error) {
	var (
		firstFreeAllocator *CIDRAllocator
		revertStack        revert.RevertStack
	)
	for _, cidrAllocator := range cidrAllocators {
		// Allocate from the first allocator that still has free CIDRs
		if cidrAllocator.IsFree() {
			firstFreeAllocator = &cidrAllocator
			break
		}
	}
	if firstFreeAllocator == nil {
		return nil, nil, &ErrAllocatorFull{}
	}
	cidr, err = (*firstFreeAllocator).AllocateNext()
	if err != nil {
		return nil, nil, err
	}
	revertStack.Push(func() error {
		return (*firstFreeAllocator).Release(cidr)
	})
	return revertStack.Revert, nil, err
}
