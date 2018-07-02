// Copyright 2016-2018 Authors of Cilium
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

package kvstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"

	consulAPI "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"
)

const (
	consulName = "consul"

	// optAddress is the string representing the key mapping to the value of the
	// address for Consul.
	optAddress = "consul.address"

	// maxLockRetries is the number of retries attempted when acquiring a lock
	maxLockRetries = 10
)

type consulModule struct {
	opts   backendOptions
	config *consulAPI.Config
}

var (
	//consulDummyAddress can be overwritten from test invokers using ldflags
	consulDummyAddress = "127.0.0.1:8501"

	module = &consulModule{
		opts: backendOptions{
			optAddress: &backendOption{
				description: "Addresses of consul cluster",
			},
		},
	}
)

func init() {
	// register consul module for use
	registerBackend(consulName, module)
}

func (c *consulModule) createInstance() backendModule {
	cpy := *module
	return &cpy
}

func (c *consulModule) getName() string {
	return consulName
}

func (c *consulModule) setConfigDummy() {
	c.config = consulAPI.DefaultConfig()
	c.config.Address = consulDummyAddress
}

func (c *consulModule) setConfig(opts map[string]string) error {
	return setOpts(opts, c.opts)
}

func (c *consulModule) getConfig() map[string]string {
	return getOpts(c.opts)
}

func (c *consulModule) newClient() (BackendOperations, error) {
	if c.config == nil {
		consulAddr, ok := c.opts[optAddress]
		if !ok {
			return nil, fmt.Errorf("invalid consul configuration, please specify %s option", optAddress)
		}

		addr := consulAddr.value
		consulSplitAddr := strings.Split(addr, "://")
		if len(consulSplitAddr) == 2 {
			addr = consulSplitAddr[1]
		} else if len(consulSplitAddr) == 1 {
			addr = consulSplitAddr[0]
		}

		c.config = consulAPI.DefaultConfig()
		c.config.Address = addr
	}

	client, err := newConsulClient(c.config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

var (
	maxRetries = 30
)

type consulClient struct {
	*consulAPI.Client
	lease       string
	controllers *controller.Manager
}

func newConsulClient(config *consulAPI.Config) (BackendOperations, error) {
	var (
		c   *consulAPI.Client
		err error
	)
	if config != nil {
		c, err = consulAPI.NewClient(config)
	} else {
		c, err = consulAPI.NewClient(consulAPI.DefaultConfig())
	}
	if err != nil {
		return nil, err
	}

	boff := backoff.Exponential{Min: time.Duration(100) * time.Millisecond}
	log.Info("Waiting for consul to elect a leader")

	for i := 0; i < maxRetries; i++ {
		var leader string
		leader, err = c.Status().Leader()

		if err == nil {
			if leader != "" {
				// happy path
				break
			} else {
				err = errors.New("timeout while waiting for leader to be elected")
			}
		}

		boff.Wait()
	}

	if err != nil {
		log.WithError(err).Fatal("Unable to contact consul server")
	}

	entry := &consulAPI.SessionEntry{
		TTL:      fmt.Sprintf("%ds", int(LeaseTTL.Seconds())),
		Behavior: consulAPI.SessionBehaviorDelete,
	}

	lease, _, err := c.Session().Create(entry, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create default lease: %s", err)
	}

	client := &consulClient{
		Client:      c,
		lease:       lease,
		controllers: controller.NewManager(),
	}

	client.controllers.UpdateController(fmt.Sprintf("consul-lease-keepalive-%p", c),
		controller.ControllerParams{
			DoFunc: func() error {
				_, _, err := c.Session().Renew(lease, nil)
				return err
			},
			RunInterval: KeepAliveInterval,
		},
	)

	return client, nil
}

func (c *consulClient) LockPath(path string) (kvLocker, error) {
	lockKey, err := c.LockOpts(&consulAPI.LockOptions{Key: getLockPath(path)})
	if err != nil {
		return nil, err
	}

	for retries := 0; retries < maxLockRetries; retries++ {
		ch, err := lockKey.Lock(nil)
		switch {
		case err != nil:
			return nil, err
		case ch == nil && err == nil:
			Trace("Acquiring lock timed out, retrying", nil, logrus.Fields{fieldKey: path, logfields.Attempt: retries})
		default:
			return lockKey, err
		}
	}

	return nil, fmt.Errorf("maximum retries (%d) reached", maxLockRetries)
}

// FIXME: Obsolete, remove
func (c *consulClient) InitializeFreeID(path string, firstID uint32) error {
	freeIDByte, err := json.Marshal(firstID)
	if err != nil {
		return err
	}
	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	p := &consulAPI.KVPair{Key: path, Value: freeIDByte}
	lockPair := &consulAPI.KVPair{Key: getLockPath(path), Session: session}
	log.Debug("Trying to acquire lock for free ID...")
	acq, _, err := c.KV().Acquire(lockPair, nil)
	if err != nil {
		return err
	}
	if !acq {
		return nil
	}
	defer c.KV().Release(lockPair, nil)

	log.Debug("Trying to acquire free ID...")
	k, _, err := c.KV().Get(path, nil)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}
	_, err = c.KV().Put(p, nil)
	if err != nil {
		return err
	}

	return nil
}

// FIXME: Obsolete, remove
func (c *consulClient) SetValue(k string, v interface{}) error {
	var err error
	lblKey := &consulAPI.KVPair{Key: k}
	lblKey.Value, err = json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.KV().Put(lblKey, nil)
	return err
}

// FIXME: Obsolete, remove
func (c *consulClient) GetValue(k string) (json.RawMessage, error) {
	pair, _, err := c.KV().Get(k, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return json.RawMessage(pair.Value), nil
}

// GetMaxID returns the maximum possible free UUID stored in consul.
//
// FIXME: Obsolete, remove
func (c *consulClient) GetMaxID(key string, firstID uint32) (uint32, error) {
	k, _, err := c.KV().Get(key, nil)
	if err != nil {
		return 0, err
	}
	if k == nil {
		// FreeID is empty? We should set it out!
		if err := c.InitializeFreeID(key, firstID); err != nil {
			return 0, err
		}
		k, _, err = c.KV().Get(key, nil)
		if err != nil {
			return 0, err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to retrieve last free ID because the key is always empty\n"
			log.Error(errMsg)
			return 0, fmt.Errorf(errMsg)
		}
	}
	var freeID uint32
	if err := json.Unmarshal(k.Value, &freeID); err != nil {
		return 0, err
	}
	return freeID, nil
}

// FIXME: Obsolete, remove
func (c *consulClient) SetMaxID(key string, firstID, maxID uint32) error {
	k, _, err := c.KV().Get(key, nil)
	if err != nil {
		return err
	}
	if k == nil {
		// FreeIDs is empty? We should set it out!
		if err := c.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, _, err = c.KV().Get(key, nil)
		if err != nil {
			return err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Error(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	k.Value, err = json.Marshal(maxID)
	if err != nil {
		return err
	}
	_, err = c.KV().Put(k, nil)
	return err
}

// FIXME: Obsolete, remove
func (c *consulClient) setMaxL3n4AddrID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

// FIXME: Obsolete, remove
func (c *consulClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	setIDtoL3n4Addr := func(id uint32) error {
		lAddrID.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(lAddrID.ID), 10))
		if err := c.SetValue(keyPath, lAddrID); err != nil {
			return err
		}
		return c.setMaxL3n4AddrID(id + 1)
	}

	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		lockPair := &consulAPI.KVPair{Key: getLockPath(keyPath), Session: session}
		acq, _, err := c.KV().Acquire(lockPair, nil)
		if err != nil {
			return false, err
		}
		defer c.KV().Release(lockPair, nil)

		if acq {
			svcKey, _, err := c.KV().Get(keyPath, nil)
			if err != nil {
				return false, err
			}
			if svcKey == nil {
				return false, setIDtoL3n4Addr(*incID)
			}
			var consulL3n4AddrID types.L3n4AddrID
			if err := json.Unmarshal(svcKey.Value, &consulL3n4AddrID); err != nil {
				return false, err
			}
			if consulL3n4AddrID.ID == 0 {
				log.WithField(logfields.Identity, baseID).Info("Recycling Service ID")
				return false, setIDtoL3n4Addr(*incID)
			}
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of serviceIDs available")
		}
		// Only retry if we have incremented the service ID
		return true, nil
	}

	beginning := baseID
	for {
		retry, err := acquireFreeID(beginning, &baseID)
		if err != nil {
			return err
		} else if !retry {
			return nil
		}
	}
}

// Watch starts watching for changes in a prefix
func (c *consulClient) Watch(w *Watcher) {
	// Last known state of all KVPairs matching the prefix
	localState := map[string]consulAPI.KVPair{}
	nextIndex := uint64(0)

	qo := consulAPI.QueryOptions{}

	for {
		// Initialize sleep time to a millisecond as we don't
		// want to sleep in between successful watch cycles
		sleepTime := 1 * time.Millisecond

		qo.WaitIndex = nextIndex
		pairs, q, err := c.KV().List(w.prefix, &qo)
		if err != nil {
			sleepTime = 5 * time.Second
			Trace("List of Watch failed", err, logrus.Fields{fieldPrefix: w.prefix, fieldWatcher: w.name})
		}

		if q != nil {
			nextIndex = q.LastIndex
		}

		// timeout while watching for changes, re-schedule
		if qo.WaitIndex != 0 && (q == nil || q.LastIndex == qo.WaitIndex) {
			continue
		}

		for _, newPair := range pairs {
			oldPair, ok := localState[newPair.Key]

			// Keys reported for the first time must be new
			if !ok {
				if newPair.CreateIndex != newPair.ModifyIndex {
					log.Debugf("consul: Previously unknown key %s received with CreateIndex(%d) != ModifyIndex(%d)",
						newPair.Key, newPair.CreateIndex, newPair.ModifyIndex)
				}

				w.Events <- KeyValueEvent{
					Typ:   EventTypeCreate,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
			} else if oldPair.ModifyIndex != newPair.ModifyIndex {
				w.Events <- KeyValueEvent{
					Typ:   EventTypeModify,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
			}

			// Everything left on localState will be assumed to
			// have been deleted, therefore remove all keys in
			// localState that still exist in the kvstore
			delete(localState, newPair.Key)
		}

		for k, deletedPair := range localState {
			w.Events <- KeyValueEvent{
				Typ:   EventTypeDelete,
				Key:   deletedPair.Key,
				Value: deletedPair.Value,
			}
			delete(localState, k)
		}

		for _, newPair := range pairs {
			localState[newPair.Key] = *newPair

		}

		// Initial list operation has been completed, signal this
		if qo.WaitIndex == 0 {
			w.Events <- KeyValueEvent{Typ: EventTypeListDone}
		}

		select {
		case <-time.After(sleepTime):
		case <-w.stopWatch:
			close(w.Events)
			return
		}
	}
}

func (c *consulClient) Status() (string, error) {
	leader, err := c.Client.Status().Leader()
	return "Consul: " + leader, err
}

func (c *consulClient) DeletePrefix(path string) error {
	_, err := c.Client.KV().DeleteTree(path, nil)
	return err
}

// Set sets value of key
func (c *consulClient) Set(key string, value []byte) error {
	_, err := c.KV().Put(&consulAPI.KVPair{Key: key, Value: value}, nil)
	return err
}

// Delete deletes a key
func (c *consulClient) Delete(key string) error {
	_, err := c.KV().Delete(key, nil)
	return err
}

// Get returns value of key
func (c *consulClient) Get(key string) ([]byte, error) {
	pair, _, err := c.KV().Get(key, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (c *consulClient) GetPrefix(prefix string) ([]byte, error) {
	pairs, _, err := c.KV().List(prefix, nil)
	if err != nil {
		return nil, err
	}

	if len(pairs) == 0 {
		return nil, nil
	}

	return pairs[0].Value, nil
}

// Update creates or updates a key with the value
func (c *consulClient) Update(key string, value []byte, lease bool) error {
	k := &consulAPI.KVPair{Key: key, Value: value}

	if lease {
		k.Session = c.lease
	}

	_, err := c.KV().Put(k, nil)
	return err
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (c *consulClient) CreateOnly(key string, value []byte, lease bool) error {
	k := &consulAPI.KVPair{
		Key:         key,
		Value:       value,
		CreateIndex: 0,
	}

	if lease {
		k.Session = c.lease
	}

	success, _, err := c.KV().CAS(k, nil)
	if err != nil {
		return fmt.Errorf("unable to compare-and-swap: %s", err)
	}
	if !success {
		return fmt.Errorf("compare-and-swap unsuccessful")
	}

	return nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (c *consulClient) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	// Consul does not support transactions which would allow to check for
	// the presence of a conditional key if the key is not the key being
	// manipulated
	//
	// Lock the conditional key to serialize all CreateIfExists() calls
	l, err := LockPath(condKey)
	if err != nil {
		return fmt.Errorf("unable to lock condKey for CreateIfExists: %s", err)
	}

	defer l.Unlock()

	// Create the key if it does not exist
	if err := c.CreateOnly(key, value, lease); err != nil {
		return err
	}

	// Consul does not support transactions which would allow to check for
	// the presence of another key
	masterKey, err := c.Get(condKey)
	if err != nil || masterKey == nil {
		c.Delete(key)
		return fmt.Errorf("conditional key not present")
	}

	return nil
}

// ListPrefix returns a map of matching keys
func (c *consulClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	pairs, _, err := c.KV().List(prefix, nil)
	if err != nil {
		return nil, err
	}

	p := KeyValuePairs(make(map[string][]byte, len(pairs)))
	for i := 0; i < len(pairs); i++ {
		p[pairs[i].Key] = pairs[i].Value
	}

	return p, nil
}

// Close closes the consul session
func (c *consulClient) Close() {
	if c.controllers != nil {
		c.controllers.RemoveAll()
	}
	if c.lease != "" {
		c.Session().Destroy(c.lease, nil)
	}
}

// GetCapabilities returns the capabilities of the backend
func (c *consulClient) GetCapabilities() Capabilities {
	return Capabilities(0)
}

// Encode encodes a binary slice into a character set that the backend supports
func (c *consulClient) Encode(in []byte) string {
	return base64.URLEncoding.EncodeToString([]byte(in))
}

// Decode decodes a key previously encoded back into the original binary slice
func (c *consulClient) Decode(in string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(in)
}

// ListAndWatch implements the BackendOperations.ListAndWatch using consul
func (c *consulClient) ListAndWatch(name, prefix string, chanSize int) *Watcher {
	w := newWatcher(name, prefix, chanSize)

	log.WithField(fieldWatcher, w).Debug("Starting watcher...")

	go c.Watch(w)

	return w
}
