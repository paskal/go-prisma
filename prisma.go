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
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// prismaRenewTimeout defines how often auth token is renewed,
// after 10 minutes it gets invalidated and new complete login is required
const prismaRenewTimeout = time.Minute * 3
const defaultHTTPClientTimeout = time.Second * 5

// API is an object to make API calls to Palo Alto Prisma Cloud
type API struct {
	username          string
	password          string
	apiURL            string
	token             string
	httpClientTimeout time.Duration
	tokenRenewTime    time.Time
	tokenLock         sync.Mutex
}

// service structure for authentication API endpoints response unmarshaling
type authResponse struct {
	Token string `json:"token"`
}

// NewClient returns new Prisma API client instance.
//
// username and password are the same as API Key and API Password.
// Recommended value for apiURL is https://api.eu.prismacloud.io
func NewClient(username, password, apiURL string) *API {
	return &API{username: username, password: password, apiURL: apiURL, httpClientTimeout: defaultHTTPClientTimeout}
}

// Call does request to API with specified method
// and returns response body on success.
// Thread safe.
func (p *API) Call(method, url string, body io.Reader) ([]byte, error) {
	p.tokenLock.Lock()
	if time.Since(p.tokenRenewTime) > prismaRenewTimeout {
		if err := p.authenticate(); err != nil {
			p.tokenLock.Unlock()
			return nil, errors.Wrap(err, "error getting auth token")
		}
	}
	token := p.token
	p.tokenLock.Unlock()
	return callWithToken(method, p.apiURL+url, token, body)
}

// SetTimeout sets http timeout for Prisma requests to specified value.
// Thread safe.
func (p *API) SetTimeout(t time.Duration) {
	p.tokenLock.Lock()
	p.httpClientTimeout = t
	p.tokenLock.Unlock()
}

// authenticate gets or renews the API authentication token
// https://api.docs.prismacloud.io/reference#login
func (p *API) authenticate() error {
	p.tokenRenewTime = time.Now()
	var res = &authResponse{}
	switch p.token {
	case "":
		// no token set yet, first login
		loginData := map[string]string{"username": p.username, "password": p.password}
		jsonValue, err := json.Marshal(loginData)
		if err != nil {
			return errors.Wrap(err, "error marshaling login data")
		}
		data, err := callWithToken("POST", p.apiURL+"/login", "", bytes.NewBuffer(jsonValue))
		if err != nil {
			return errors.Wrapf(err, "error logging in with user %q", p.username)
		}
		if err := json.Unmarshal(data, res); err != nil {
			return errors.Wrap(err, "error obtaining token from login response")
		}
		p.token = res.Token
	default:
		// token is set and we will try to renew it
		data, err := callWithToken("GET", p.apiURL+"/auth_token/extend", p.token, nil)
		if err != nil {
			log.Printf("[INFO] Error extending token, will re-login, %v", err)
			p.token = ""
			return p.authenticate()
		}
		if err := json.Unmarshal(data, res); err != nil {
			log.Printf("[INFO] Error obtaining token from extend token response, will re-login, %v", err)
			p.token = ""
			return p.authenticate()
		}
		p.token = res.Token
	}
	return nil
}

// callWithToken does request to Prisma API with specified method and
// provided token and returns response body on success.
// Thread safe.
func callWithToken(method, fullURL, token string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, errors.Wrap(err, "error creating request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-redlock-auth", token)
	httpClient := http.Client{Timeout: defaultHTTPClientTimeout}
	response, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error making request")
	}
	data, err := ioutil.ReadAll(response.Body)
	defer response.Body.Close() // nolint:errcheck
	if err != nil {
		return nil, errors.Wrapf(err, "error reading response body, response body: %q", data)
	}
	switch response.StatusCode {
	case http.StatusOK:
		return data, nil
	case http.StatusUnauthorized:
		return nil, errors.Errorf("authentication error on request, response body: %q", data)
	case http.StatusBadRequest:
		return nil, errors.Errorf("bad request parameters, check your request body, response body: %q", data)
	case http.StatusInternalServerError:
		return nil, errors.Errorf("server internal error during request processing, response body: %q", data)
	default:
		return nil, errors.Errorf("%v, response body: %q", response.Status, data)
	}
}
