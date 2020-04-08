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

package main

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

// CRDBackoff is the backoff for initial creation of CRDs by cilium-agent.
var CRDBackoff = wait.Backoff{
	Duration: 30 * time.Second,
	Steps:    15,
	Factor:   1.0,
	Jitter:   0.1,
}

func getCRD(client clientset.Interface, CRDName string) error {
	_, err := client.ApiextensionsV1beta1().CustomResourceDefinitions().Get(context.TODO(), CRDName, metav1.GetOptions{})
	return err
}

func waitForCRDWithBackoff(client clientset.Interface, backoff wait.Backoff, CRDname string) error {
	if err := retry.OnError(retry.DefaultBackoff, k8serrors.IsNotFound, func() error {
		return getCRD(client, CRDname)
	}); err != nil {
		return errors.Wrapf(err, "timeout exceeded when waiting for CRD %s", CRDname)
	}
	return nil
}

// waitForCRD waits for the given CRD to be available until the timeout defined
// by CRDRetry. Returns an error when timeout exceeded.
func waitForCRD(client clientset.Interface, CRDname string) error {
	return waitForCRDWithBackoff(client, CRDBackoff, CRDname)
}
