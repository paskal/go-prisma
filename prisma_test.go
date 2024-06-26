// Copyright 2020 Dmitry Verkhoturov <paskal.07@gmail.com>
// Copyright 2019 Booking.com
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

package prisma

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestApiRequest(t *testing.T) {
	// prepare servers
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/login", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		assert.Equal(t, "test_text", buf.String())
		_, _ = fmt.Fprint(w, "one, two, three")
	}))
	defer goodServer.Close()
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("Content-Length", "1")
	}))
	defer badServer.Close()
	serverStatusUnauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer serverStatusUnauthorized.Close()
	serverStatusBadRequest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer serverStatusBadRequest.Close()
	serverStatusInternalServerError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverStatusInternalServerError.Close()
	serverStatusNotFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer serverStatusNotFound.Close()

	var testAPIRequestsDataset = []struct {
		description  string
		serverURL    string
		method       string
		url          string
		error        string
		responseBody []byte
		body         io.Reader
	}{
		{description: "bad port",
			serverURL: "http://[::1]:namedport", method: "POST",
			error: `error getting auth token: error logging in with user "": error creating request: ` +
				`parse "http://[::1]:namedport/login": invalid port ":namedport" after host`},
		{description: "nonexistent url",
			serverURL: "nonexistent_url", method: "POST",
			error: `error making request: Post "nonexistent_url": unsupported protocol scheme ""`},
		{description: "good response",
			serverURL: goodServer.URL, method: "POST", url: "/login",
			responseBody: []byte("one, two, three"), body: bytes.NewReader([]byte("test_text"))},
		{description: "bad response",
			serverURL: badServer.URL, method: "GET", url: "/",
			error: "error reading response body, response body: \"\": unexpected EOF"},
		{description: "authentication error",
			serverURL: serverStatusUnauthorized.URL, method: "GET",
			error: "authentication error on request, response body: \"\""},
		{description: "bad request error",
			serverURL: serverStatusBadRequest.URL, method: "GET",
			error: "bad request parameters, check your request body, response body: \"\""},
		{description: "internal error",
			serverURL: serverStatusInternalServerError.URL, method: "GET",
			error: "server internal error during request processing, response body: \"\""},
		{description: "not found error",
			serverURL: serverStatusNotFound.URL, method: "GET",
			error: "404 Not Found, response body: \"\""},
	}

	// start tests
	p := API{}

	for i, x := range testAPIRequestsDataset {
		i := i
		x := x
		t.Run(x.description, func(t *testing.T) {
			p.apiURL = x.serverURL
			data, err := p.Call(x.method, x.url, x.body)
			if x.error != "" {
				assert.EqualError(t, err, x.error, "Test case %d error check failed", i)
			} else {
				assert.NoError(t, err, "Test case %d error check failed", i)
			}
			if x.responseBody != nil {
				assert.Equal(t, x.responseBody, data, "Test case %d response data check failed", i)
			} else {
				assert.Nil(t, data, "Test case %d response data check failed", i)
			}
		})
	}
}

func TestApiRequestParallel(t *testing.T) {
	// prepare server
	// server is not very parallel-safe, but works up to go test -count=50 ./...
	var firstAuth bool
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !firstAuth {
			assert.Equal(t, "/login", r.URL.Path)
			assert.Equal(t, "POST", r.Method)
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			assert.Equal(t, "{\"password\":\"test_password\",\"username\":\"test_user\"}", buf.String())
			_, _ = fmt.Fprint(w, "{\"token\":\"test_token\"}")
			firstAuth = true
			return
		}
		assert.Equal(t, "/check", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		_, _ = fmt.Fprint(w, "pong")
	}))
	defer goodServer.Close()

	// start test
	wg := sync.WaitGroup{}
	start := make(chan struct{})
	p := NewClient("test_user", "test_password", goodServer.URL)

	for i := 0; i < 300; i++ {
		wg.Add(1) // nolint:gomnd
		go func(wg *sync.WaitGroup, i int) {
			<-start
			resp, err := p.Call("GET", "/check", nil)
			assert.NoError(t, err, "Test case %d error check failed", i)
			assert.Equal(t, "pong", string(resp), "Test case %d API object token check failed", i)
			wg.Done()
		}(&wg, i)
	}
	close(start)
	wg.Wait()
}

func TestNewClient(t *testing.T) {
	// prepare servers
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/login", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		assert.Equal(t, "{\"password\":\"test_password\",\"username\":\"test_user\"}", buf.String())
		_, _ = fmt.Fprint(w, "{\"token\":\"test_token\"}")
	}))
	defer goodServer.Close()
	goodRenewServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/auth_token/extend", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		_, _ = fmt.Fprint(w, "{\"token\":\"test_token_renewed\"}")
	}))
	defer goodRenewServer.Close()
	badRenewServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer badRenewServer.Close()
	badEmptyServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer badEmptyServer.Close()
	badAnswerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.URL.Path, "/login")
		assert.Equal(t, "POST", r.Method)
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		assert.Equal(t, "{\"password\":\"\",\"username\":\"\"}", buf.String())
		_, _ = fmt.Fprint(w, "not_json")
	}))
	defer badAnswerServer.Close()

	var testAPIRequestsDataset = []struct {
		description   string
		serverURL     string
		username      string
		password      string
		error         string
		responseToken string
		setToken      string
	}{
		{description: "nonexistent url",
			serverURL: "nonexistent_url", username: "test_username",
			error: `error logging in with user "test_username": error making request: ` +
				`Post "nonexistent_url/login": unsupported protocol scheme ""`},
		{description: "good server",
			serverURL: goodServer.URL, username: "test_user", password: "test_password", responseToken: "test_token"},
		{description: "bad server answer",
			serverURL: badAnswerServer.URL,
			error:     "error obtaining token from login response: invalid character 'o' in literal null (expecting 'u')"},
		{description: "good renew server",
			serverURL: goodRenewServer.URL, username: "test_user", password: "test_password",
			setToken: "old_good_token", responseToken: "test_token_renewed"},
		{description: "bad renew server",
			serverURL: badRenewServer.URL, username: "test_user", password: "test_password", setToken: "old_bad_token",
			error: `error logging in with user "test_user": authentication error on request, response body: ""`},
		{description: "empty answer server",
			serverURL: badEmptyServer.URL, username: "test_user", password: "test_password", setToken: "old_bad_token",
			error: "error obtaining token from login response: unexpected end of JSON input"},
	}

	// start tests

	for i, x := range testAPIRequestsDataset {
		i := i
		x := x
		t.Run(x.description, func(t *testing.T) {
			p := NewClient(x.username, x.password, x.serverURL)
			p.token = x.setToken
			err := p.authenticate()
			if x.error != "" {
				assert.EqualError(t, err, x.error, "Test case %d error check failed", i)
			} else {
				assert.NoError(t, err, "Test case %d error check failed", i)
			}
			assert.Equal(t, x.responseToken, p.token, "Test case %d API object token check failed", i)
		})
	}
}

func TestAPI_SetTimeout(t *testing.T) {
	p := NewClient("test_user", "test_password", "")
	assert.Equal(t, defaultHTTPClientTimeout, p.httpClientTimeout)
	p.SetTimeout(time.Nanosecond)
	assert.Equal(t, time.Nanosecond, p.httpClientTimeout)
}
