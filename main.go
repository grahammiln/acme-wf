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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/dynport/gossh"         // Easier ssh client
	"github.com/renier/xmlrpc"         // XML-RPC client
	"golang.org/x/crypto/ssh/terminal" // ReadPassword support
	"miln.eu/webfaction"               // WebFaction helper functions and structures
)

// Command line arguments
var wfUsername = flag.String("u", "", "WebFaction user name (required)")
var wfPassword = flag.String("p", "", "WebFaction control panel password (optional)")
var wfServer = flag.String("s", "", "WebFaction server (optional)")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "acme-wf Copyright 2017 Graham Miln, https://miln.eu. All rights reserved.\n")
	}
	flag.Parse()

	// WebFaction username is required
	if wfUsername == nil || *wfUsername == "" {
		log.Fatal("[ERROR] Required WebFaction user name is empty or missing.")
	}

	// WebFaction control panel password is optional; interactive if not provided
	if wfPassword == nil || *wfPassword == "" {
		fmt.Print("WebFaction control panel password: ")
		wfp, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			log.Fatal(fmt.Sprintf("[ERROR] Unable to read password: %v", err))
		}
		fmt.Print("\n")
		*wfPassword = string(wfp)
	}
	if wfPassword == nil || *wfPassword == "" {
		log.Fatal("[ERROR] Required WebFaction control panel password is empty or missing.")
	}

	// Connect to WebFaction via XML-RPC API
	wf, err := xmlrpc.NewClient("https://api.webfaction.com/", nil, time.Minute)
	if err != nil {
		log.Fatal(fmt.Sprintf("[ERROR] Unable to set up WebFaction XML-RPC client: %v", err))
	}
	defer wf.Close()

	// `login` to WebFaction to get a session token and user information
	var r []interface{}
	log.Printf("[INFO] Logging into WebFaction as: '%v'", *wfUsername)
	if err = wf.Call("login", []interface{}{*wfUsername, *wfPassword, *wfServer, webfaction.APIVersion}, &r); err != nil {
		log.Fatal(fmt.Sprintf("[ERROR] WebFaction `login` failed: %s", err))
	}
	var sID string
	var s webfaction.Session
	if err := webfaction.Unmarshal(r, &sID, &s); err != nil {
		log.Fatal(fmt.Sprintf("[ERROR] WebFaction invalid session response: %s", err))
	}
	log.Printf("[INFO] Established WebFaction session as user '%s' for server '%s'", s.Username, s.WebServer)

	// `list_certificates` to get list of existing certificates; needed to decide between `update_certificate` and `create_certificate`
	log.Printf("[INFO] Requesting WebFaction certificate list")
	if err = wf.Call("list_certificates", sID, &r); err != nil {
		log.Fatal(fmt.Sprintf("[ERROR] WebFaction `list_certificates` failed: %s", err))
	}
	var certs []*webfaction.Certificate
	if err := webfaction.Unmarshal(r, &certs); err != nil {
		log.Fatal(fmt.Sprintf("[ERROR] WebFaction invalid session response: %s", err))
	}

	// Nothing beyond flags provided on the command line; list known WebFaction certificates and exit
	if flag.NArg() == 0 {
		for _, c := range certs {
			log.Printf("[INFO] Found WebFaction certificate: '%s' expires %s, for domains '%s'", c.Name, c.RawExpiryDate, c.RawDomains)
		}
		log.Printf("[WARN] Nothing to do because no domains provided; list domains on command line to create or update.")
		return
	}

	// Connect to the server via ssh to collect acme.sh certificate files
	sshserver := fmt.Sprintf("%s.webfaction.com", strings.ToLower(s.WebServer))
	log.Printf("[INFO] ssh to '%s@%s' to read certificates", s.Username, sshserver)
	ssh := gossh.New(sshserver, s.Username)
	defer ssh.Close()

	// Path to base directory where acme.sh stores certificates
	acmepath := path.Join(s.Home, s.Username, ".acme.sh")

	// Enumerate non-flag arguments; each is assumed to be a acme.sh managed domain name
	for _, domain := range flag.Args() {
		log.Printf("[INFO] Working on domain: '%v'", domain)

		// Get the acme.sh certificate files for this domain from the server
		domainpath := path.Join(acmepath, domain)
		// ...PEM encoded domain certificate
		pemcert, err := sshGetFile(ssh, path.Join(domainpath, fmt.Sprintf("%s.cer", domain)))
		if err != nil {
			log.Fatal(fmt.Sprintf("[ERROR] Unable to read acme.sh certificate for domain '%s': %s", domain, err))
		}
		// ...PEM encoded certificate key
		pemkey, err := sshGetFile(ssh, path.Join(domainpath, fmt.Sprintf("%s.key", domain)))
		if err != nil {
			log.Fatal(fmt.Sprintf("[ERROR] Unable to read acme.sh private key for domain '%s': %s", domain, err))
		}
		// ...PEM encoded chain certificate
		pemchain, err := sshGetFile(ssh, path.Join(domainpath, "ca.cer"))
		if err != nil {
			log.Fatal(fmt.Sprintf("[ERROR] Unable to read acme.sh certificate chain for domain '%s': %s", domain, err))
		}

		// WebFaction does not accept cert names with periods `.`
		dname := strings.Replace(domain, ".", "_", -1) // replace periods `.` with underscore `_`

		// Search for WebFaction certificate entry with this name
		known := false
		for _, c := range certs {
			if c.Name == dname {
				known = true
				break
			}
		}
		// Update if certificate name is known, otherwise create a new entry
		certmethod := "update_certificate"
		if !known {
			certmethod = "create_certificate"
		}

		log.Printf("[INFO] Requesting WebFaction `%s` for %s (%s)", certmethod, dname, domain)
		if err = wf.Call(certmethod, []interface{}{sID, dname, pemcert, pemkey, pemchain}, nil); err != nil {
			log.Fatal(fmt.Sprintf("[ERROR] WebFaction `%s` failed for '%s':  %s", dname, err))
		}
		log.Printf("[INFO] Successfully called WebFaction `%s` for %s (%s)", certmethod, dname, domain)
	}
}

// Get a file from the given path.
func sshGetFile(ssh *gossh.Client, p string) (string, error) {
	log.Printf("[INFO] Reading '%s' via ssh", p)
	cmd := fmt.Sprintf("cat '%s'", p)
	rsp, err := ssh.Execute(cmd)
	if err != nil {
		log.Printf("[ERROR] ssh error reading file with '%s': %s", cmd, err)
		return "", err
	}
	return rsp.Stdout(), nil
}
