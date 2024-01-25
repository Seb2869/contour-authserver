// Copyright Project Contour Authors
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

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Bearer watches Secrets for Bearer files and uses them for HTTP Basic Authentication.
type Bearer struct {
	Log      logr.Logger
	Tokens   []string
	Realm    string
	Client   client.Client
	Selector labels.Selector

	Lock sync.Mutex
}

var _ Checker = &Bearer{}

// Set the Bearer file to use.
func (h *Bearer) Set(tokens []string) {
	h.Lock.Lock()
	defer h.Lock.Unlock()

	h.Tokens = tokens
}

// Match authenticates the credential against the Bearer file.
func (h *Bearer) Match(token string) bool {
	h.Lock.Lock()
	defer h.Lock.Unlock()
	for _, t := range h.Tokens {
		if token == t {
			return true
		}
	}
	return false
}

// Check ...
func (h *Bearer) Check(ctx context.Context, request *Request) (*Response, error) {
	h.Log.Info("checking request",
		"host", request.Request.Host,
		"path", request.Request.URL.Path,
		"id", request.ID,
	)

	auth := request.Request.Header.Get("Authorization")
	bearer := strings.SplitN(auth, " ", 2)

	// If there's an "Authorization" header and we can verify
	// it, succeed and inject some headers to tell the origin
	// what  we did.
	if auth != "" && len(bearer) > 1 && bearer[0] == "Bearer" && h.Match(bearer[1]) {
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler": {"Bearer"},
				"Auth-Realm":   {h.Realm},
			},
		}

		// Reflect the authorization check context into the response headers.
		for k, v := range request.Context {
			fmt.Println(k, v)
			key := fmt.Sprintf("Auth-Context-%s", k)
			key = http.CanonicalHeaderKey(key) // XXX(jpeach) this will not transform invalid characters

			authorized.Header.Add(key, v)
		}

		return &Response{
			Allow:    true,
			Response: authorized,
		}, nil
	}

	// If there's no "Authorization" header, or the authentication
	// failed, send an authenticate request.
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
		},
	}, nil
}

// Reconcile ...
func (h *Bearer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var opts []client.ListOption

	if h.Selector != nil {
		opts = append(opts, client.MatchingLabelsSelector{Selector: h.Selector})
	}

	// First, find all the auth secrets.
	secrets := &v1.SecretList{}
	if err := h.Client.List(ctx, secrets, opts...); err != nil {
		return ctrl.Result{}, err
	}

	var tokens []string

	for _, s := range secrets.Items {
		// Only look at bearer secrets.
		if s.Annotations[AnnotationAuthType] != "bearer" {
			continue
		}

		// Accept the secret if it is for our realm or for any realm.
		if realm := s.Annotations[AnnotationAuthRealm]; realm != "" {
			if realm != h.Realm && realm != "*" {
				continue
			}
		}

		// Check for the "auth" key, which is the format used by ingress-nginx.
		authData, ok := s.Data["auth"]
		if !ok {
			h.Log.Info("skipping Secret without \"auth\" key",
				"name", s.Name, "namespace", s.Namespace)
			continue
		}

		tokens = append(tokens, string(authData))
	}

	h.Set(tokens)

	return ctrl.Result{}, nil
}

// RegisterWithManager ...
func (h *Bearer) RegisterWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(h)
}
