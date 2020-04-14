.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _gsg_ipam_crd_operator:

*****************************
CRD-backed by Cilium Operator
*****************************

This is a quick tutorial walking through how to enable CRD-backed by Cilium
Operator. The purpose of this tutorial is to show how components are configured
and resources interact with each other to enable users to automate or extend on
their own.

For more details, see the section :ref:`ipam_crd_operator`

Enable Operator IPAM mode
=========================

#. Setup Cilium for Kubernetes using helm with the options:
   ``--set global.ipam.mode=operator``.
#. Depending if you are using IPv4 and / or IPv6, you might want to adjust
   the ``podCIDR`` allocated for your cluster's pods with the options:

   * ``--set global.ipam.operator.ipv4PodCIDR=<IPv4CIDR>``
   * ``--set global.ipam.operator.ipv6PodCIDR=<IPv6CIDR>``

#. To adjust the CIDR size that should be allocated for each node you can use
   the following options:

   * ``--set global.ipam.operator.nodeCIDRMaskSizeIPv4=<IPv4MaskSize>``
   * ``--set global.ipam.operator.nodeCIDRMaskSizeIPv6=<IPv6MaskSize>``

#. Deploy Cilium and Cilium-Operator. Cilium will automatically wait until the
   ``podCIDR`` is allocated for its node by Cilium Operator.

Validate installation
=====================

#. Validate that Cilium has started up correctly

   ::

           cilium status --all-addresses
           KVStore:                Ok   etcd: 1/1 connected, has-quorum=true: https://192.168.33.11:2379 - 3.3.12 (Leader)
           [...]
           IPAM:                   IPv4: 2/256 allocated,
           Allocated addresses:
             10.0.0.1 (router)
             10.0.0.3 (health)

#. Validate the ``spec.IPAM.PodCIDRs`` section:

   ::

       kubectl get cn k8s1 -o yaml
       apiVersion: cilium.io/v2
       kind: CiliumNode
       metadata:
         name: k8s1
         [...]
       spec:
         ipam:
           podCIDRs:
             - 10.0.0.0/24
