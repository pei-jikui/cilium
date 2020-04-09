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

// +build !privileged_tests

package peer

import (
	"net"
	"sync"
	"testing"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/stretchr/testify/assert"
)

func TestService_Notify(t *testing.T) {
	type args struct {
		init   []node.Node
		add    []node.Node
		update []node.Node
		del    []node.Node
	}
	tests := []struct {
		name string
		args args
		want []*peerpb.ChangeNotification
	}{
		{
			name: "add 4 nodes",
			args: args{
				init: []node.Node{
					{
						Name: "zero",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					},
				},
				add: []node.Node{
					{
						Name: "one",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				},
			},
		}, {
			name: "delete 3 nodes",
			args: args{
				init: []node.Node{
					{
						Name: "zero",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
				del: []node.Node{
					{
						Name: "one",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				},
			},
		}, {
			name: "update 2 nodes",
			args: args{
				init: []node.Node{
					{
						Name: "zero",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
				update: []node.Node{
					{
						Name: "one",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.2")},
						},
					}, {
						Name: "two",
						IPAddresses: []node.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::65")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				}, {
					Name:    "two",
					Address: "2001:db8::65",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []*peerpb.ChangeNotification
			var wg sync.WaitGroup
			fakeServer := &FakePeerNotifyServer{
				OnSend: func(resp *peerpb.ChangeNotification) error {
					got = append(got, resp)
					wg.Done()
					return nil
				},
			}
			ready := make(chan struct{})
			cb := func(nh datapath.NodeHandler) {
				ready <- struct{}{}
			}
			notif := newNotifier(cb, tt.args.init)
			wg.Add(len(tt.args.init))
			svc := NewService(notif)
			go func() {
				err := svc.Notify(&peerpb.NotifyRequest{}, fakeServer)
				assert.NoError(t, err)
			}()
			<-ready
			for _, n := range tt.args.add {
				wg.Add(1)
				notif.notifyAdd(n)
			}
			for _, n := range tt.args.del {
				wg.Add(1)
				notif.notifyDelete(n)
			}
			for _, n := range tt.args.update {
				wg.Add(1)
				notif.notifyUpdate(n, n)
			}
			wg.Wait()
			svc.Close()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestService_NotifyWithBlockedSend(t *testing.T) {
	fakeServer := &FakePeerNotifyServer{
		OnSend: func(resp *peerpb.ChangeNotification) error {
			<-time.After(100 * time.Millisecond)
			return nil
		},
	}
	ready := make(chan struct{})
	cb := func(nh datapath.NodeHandler) {
		ready <- struct{}{}
	}
	init := []node.Node{
		{
			Name: "one",
			IPAddresses: []node.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
			},
		}, {
			Name: "two",
			IPAddresses: []node.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
			},
		}, {
			Name:    "one",
			Cluster: "test",
			IPAddresses: []node.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
			},
		}, {
			Name:    "two",
			Cluster: "test",
			IPAddresses: []node.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
			},
		},
	}
	notif := newNotifier(cb, init)
	svc := NewService(notif, serviceoption.WithSendBufferSize(2))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := svc.Notify(&peerpb.NotifyRequest{}, fakeServer)
		assert.Equal(t, ErrStreamSendBlocked, err)
	}()
	<-ready
	for _, n := range init {
		notif.notifyAdd(n)
	}
	svc.Close()
	wg.Wait()
}

type FakePeerNotifyServer struct {
	OnSend func(response *peerpb.ChangeNotification) error
	*testutils.FakeGRPCServerStream
}

func (s *FakePeerNotifyServer) Send(response *peerpb.ChangeNotification) error {
	if s.OnSend != nil {
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

type notifier struct {
	nodes       []node.Node
	subscribers map[datapath.NodeHandler]struct{}
	cb          func(nh datapath.NodeHandler)
	mu          lock.Mutex
}

var _ manager.Notifier = (*notifier)(nil)

func newNotifier(subCallback func(nh datapath.NodeHandler), nodes []node.Node) *notifier {
	return &notifier{
		nodes:       nodes,
		subscribers: make(map[datapath.NodeHandler]struct{}),
		cb:          subCallback,
	}
}

func (n *notifier) Subscribe(nh datapath.NodeHandler) {
	n.mu.Lock()
	n.subscribers[nh] = struct{}{}
	n.mu.Unlock()
	for _, e := range n.nodes {
		nh.NodeAdd(e)
	}
	if n.cb != nil {
		n.cb(nh)
	}
}

func (n *notifier) Unsubscribe(nh datapath.NodeHandler) {
	n.mu.Lock()
	delete(n.subscribers, nh)
	n.mu.Unlock()
}

func (n *notifier) notifyAdd(e node.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeAdd(e)
	}
	n.mu.Unlock()
}

func (n *notifier) notifyDelete(e node.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeDelete(e)
	}
	n.mu.Unlock()
}

func (n *notifier) notifyUpdate(o, e node.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeUpdate(o, e)
	}
	n.mu.Unlock()
}
