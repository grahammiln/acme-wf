// Copyright 2017 Graham Miln, https://miln.eu. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webfaction

// https://docs.webfaction.com/xmlrpc-api/

import (
	"strings"
)

const APIVersion = 2

type Session struct {
	WebServer  string `mapstructure:"web_server"`
	Version    int64  `mapstructure:"version"`
	Home       string `mapstructure:"home"`
	MailServer string `mapstructure:"mail_server"`
	Username   string `mapstructure:"username"`
}

// Array of certificates returned by `list_certificates`
type Certificate struct {
	Name string `xmlrpc:"name"`

	RawCertificate   string `mapstructure:"certificate"`   // PEM encoded
	RawPrivateKey    string `mapstructure:"private_key"`   // PEM encoded
	RawIntermediates string `mapstructure:"intermediates"` // PEM encoded
	RawDomains       string `mapstructure:"domains"`       // comma separated list of domains
	RawExpiryDate    string `mapstructure:"expiry_date"`
}

func (c *Certificate) Domains() []string {
	return strings.Split(c.RawDomains, ",")
}

func DecodeCertificatesFromListCertificates(listResponse []interface{}) (*Session, error) {
	// Unwrap list_certificates response
	var c []*Certificate
	if err := Unmarshal(listResponse, &c); err != nil {
		return nil, err
	}
	return nil, nil
}
