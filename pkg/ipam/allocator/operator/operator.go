// Copyright 2019-2020 Authors of Cilium
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

package operator

import (
	"fmt"
	"net"

	"github.com/cilium/ipam/cidrset"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-operator")

// AllocatorOperator is an implementation of IPAM allocator interface for AWS ENI
type AllocatorOperator struct{}

// Init sets up ENI limits based on given options
func (*AllocatorOperator) Init() error {
	return nil
}

// Start kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (*AllocatorOperator) Start(getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	log.Info("Starting Operator IP allocator...")

	var (
		iMetrics trigger.MetricsObserver
	)

	if option.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewTriggerMetrics(operatorMetrics.Namespace, "k8s_sync")
	} else {
		iMetrics = &ipamMetrics.NoOpMetricsObserver{}
	}

	var v4CIDRSet, v6CIDRSet *cidrset.CidrSet
	if len(option.Config.IPAMOperatorV4CIDR) != 0 {
		v4Addr, v4CIDR, err := net.ParseCIDR(option.Config.IPAMOperatorV4CIDR)
		if err != nil {
			return nil, err
		}
		if !ipPkg.IsIPv4(v4Addr) {
			return nil, fmt.Errorf("IPv4CIDR is not v4 family: %s", v4Addr)
		}
		if !option.Config.EnableIPv4 {
			return nil, fmt.Errorf("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v4CIDRSet, err = cidrset.NewCIDRSet(v4CIDR, option.Config.NodeCIDRMaskSizeIPv4)
		if err != nil {
			return nil, fmt.Errorf("unable to create IPv4 pod CIDR: %s", err)
		}

	}
	if len(option.Config.IPAMOperatorV6CIDR) != 0 {
		v6Addr, v6CIDR, err := net.ParseCIDR(option.Config.IPAMOperatorV6CIDR)
		if err != nil {
			return nil, err
		}
		if ipPkg.IsIPv4(v6Addr) {
			return nil, fmt.Errorf("IPv6CIDR is not v6 family: %s", v6Addr)
		}
		if !option.Config.EnableIPv6 {
			return nil, fmt.Errorf("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v6CIDRSet, err = cidrset.NewCIDRSet(v6CIDR, option.Config.NodeCIDRMaskSizeIPv6)
		if err != nil {
			return nil, fmt.Errorf("unable to create IPv6 pod CIDR: %s", err)
		}
	}

	nodeManager := ipam.NewNodesPodCIDRManager(v4CIDRSet, v6CIDRSet, getterUpdater, iMetrics)

	return nodeManager, nil
}
