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
	"errors"
	"fmt"
	"net"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/cilium/ipam/cidrset"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-operator")

// AllocatorOperator is an implementation of IPAM allocator interface for Cilium IPAM
type AllocatorOperator struct {
	v4CIDRSet, v6CIDRSet []ipam.CIDRAllocator
}

// Init sets up Cilium allocator based on given options
func (a *AllocatorOperator) Init() error {
	if len(option.Config.IPAMOperatorV4CIDR) != 0 {
		if !option.Config.EnableIPv4 {
			return errors.New("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v4Allocators, err := newCIDRSets(false, option.Config.IPAMOperatorV4CIDR, option.Config.NodeCIDRMaskSizeIPv4)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv4 allocator %w", err)
		}
		a.v4CIDRSet = v4Allocators
	}
	if len(option.Config.IPAMOperatorV6CIDR) != 0 {
		if !option.Config.EnableIPv6 {
			return errors.New("IPv6CIDR can not be set if IPv6 is not enabled")
		}
		v6Allocators, err := newCIDRSets(true, option.Config.IPAMOperatorV6CIDR, option.Config.NodeCIDRMaskSizeIPv6)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv6 allocator %w", err)
		}
		a.v6CIDRSet = v6Allocators
	}
	if len(a.v4CIDRSet)+len(a.v6CIDRSet) == 0 {
		return fmt.Errorf("either '%s' or '%s' need to be set", option.IPAMOperatorV4CIDR, option.IPAMOperatorV6CIDR)
	}
	return nil
}

// Start kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorOperator) Start(getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	log.Info("Starting Operator IP allocator...")

	var (
		iMetrics trigger.MetricsObserver
	)

	if option.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewTriggerMetrics(operatorMetrics.Namespace, "k8s_sync")
	} else {
		iMetrics = &ipamMetrics.NoOpMetricsObserver{}
	}

	nodeManager := ipam.NewNodesPodCIDRManager(a.v4CIDRSet, a.v6CIDRSet, getterUpdater, iMetrics)

	return nodeManager, nil
}

func newCIDRSets(isV6 bool, strCIDRs []string, maskSize int) ([]ipam.CIDRAllocator, error) {
	cidrAllocators := make([]ipam.CIDRAllocator, 0, len(strCIDRs))
	for _, strCIDR := range strCIDRs {
		cidrSet, err := newCIDRSet(isV6, strCIDR, maskSize)
		if err != nil {
			return nil, err
		}
		cidrAllocators = append(cidrAllocators, cidrSet)
	}
	return cidrAllocators, nil
}

func newCIDRSet(isV6 bool, strCIDR string, maskSize int) (ipam.CIDRAllocator, error) {
	addr, cidr, err := net.ParseCIDR(strCIDR)
	if err != nil {
		return nil, err
	}
	switch {
	case isV6 && ipPkg.IsIPv4(addr):
		return nil, fmt.Errorf("CIDR is not v6 family: %s", cidr)
	case !isV6 && !ipPkg.IsIPv4(addr):
		return nil, fmt.Errorf("CIDR is not v4 family: %s", cidr)
	}

	cidrSet, err := cidrset.NewCIDRSet(cidr, maskSize)
	if err != nil {
		return nil, fmt.Errorf("unable to create IPv6 pod CIDR: %s", err)
	}

	return &cidrWrapper{
		v6:      isV6,
		CidrSet: cidrSet,
	}, nil
}

type cidrWrapper struct {
	*cidrset.CidrSet
	v6 bool
}

func (a *cidrWrapper) IsIPv6() bool {
	return a.v6
}
