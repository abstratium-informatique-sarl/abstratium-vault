// Copyright 2025 abstratium informatique sàrl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abstratriumvault

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/ipv4"
	"google.golang.org/genproto/googleapis/chat/logging/v1"
)

type IpAddresses struct {
	RealIp       string
	ForwardedFor string
	Forwarded    string
	RemoteAddr   string
	TestAddr     string
}

// function to make printing IpAddresses nicer
func (ipAddresses *IpAddresses) String() string {
	return fmt.Sprintf("Real IP: %s, Forwarded For: %s, Forwarded: %s, Remote Addr: %s, Test Addr: %s", ipAddresses.RealIp, ipAddresses.ForwardedFor, ipAddresses.Forwarded, ipAddresses.RemoteAddr, ipAddresses.TestAddr)
}

var model = make(map[string]map[string]string)

func init() {

	allowedIPsEnvVar := os.Getenv("ALLOWED_IPS")
	if allowedIPsEnvVar == "" {
		allowedIPsEnvVar = "123.123.123.123:abc=def&ghi=jkl,127.0.0.1:def=2"
	}
	fmt.Printf("Config: %v\n", allowedIPsEnvVar)

	for _, ipEntry := range strings.Split(allowedIPsEnvVar, ",") {
		line := strings.Split(ipEntry, ":")
		ip := line[0]
		data := line[1]
		model[ip] = make(map[string]string)
		for _, pair := range strings.Split(data, "&") {
			split := strings.Split(pair, "=")
			key := split[0]
			value := split[1]
			model[ip][key] = value
		}
	}
	fmt.Printf("Config2: %v\n", model)
}

func VaultMain(w http.ResponseWriter, r *http.Request) {

	// TODO deleteme log all http header:
	fmt.Printf("=============\nHeaders\n")
	for name, values := range r.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
		}
	}

	// TODO deleteme log all environment variables:
	fmt.Printf("=============\nEnv\n")
	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		fmt.Printf("%s: %s\n", pair[0], pair[1])
	}

	userIPs, err := readUserIP(r)
	if err == nil {
		w.Header().Add("X-Real-IP", userIPs.RealIp)
		w.Header().Add("X-Forwarded-For", userIPs.ForwardedFor)
		w.Header().Add("Forwarded", userIPs.Forwarded)
		w.Header().Add("X-Remote-Addr", userIPs.RemoteAddr)
		w.Header().Add("X-Test-Addr", userIPs.RemoteAddr)
		fmt.Printf("Request to URL %s from %s\n", r.URL, userIPs)
		if r.Method == http.MethodGet {
			keyname := r.URL.Query().Get("keyname")
			tokens := model[userIPs.RealIp]
			logging.Printf("tokens: %v\n", tokens)
			fmt.Printf("tokens: %v\n", tokens)
			if len(tokens) == 0 {
				tokens = model[userIPs.TestAddr]
				fmt.Printf("tokens2: %v\n", tokens)
			}
			if tokens != nil {
				token := tokens[keyname]
				if token != "" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(token))
					return
				}
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("E1001"))
				return
			}
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(err.Error()))
}

// normally the two "forwarded" headers are like this, if the real IP address is 187.148.123.154:
//     X-Forwarded-For: 187.148.123.154
//     Forwarded: for="187.148.123.154";proto=https
// if the user sets "X-Forwarded-For" and "Forwarded", then they look like this:
//     Forwarded: 123.123.123.123,for="187.148.123.154";proto=https
//     X-Forwarded-For: 123.123.123.123,187.148.123.154
// if the user just sets "Forwarded", they are like this:
//     Forwarded: 123.123.123.123,for="187.148.123.154";proto=https
//	   X-Forwarded-For: 187.148.123.154
// if the user just sets "X-Forwarded-For", they are like this:
//     Forwarded: for="187.148.123.154";proto=https
// 	   X-Forwarded-For: 123.123.123.123,187.148.123.154
// if either header does not match the standard pattern, then refuse to answer
const ipv4v6Regex = `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(([0-9a-f]){1,4}(:([0-9a-f]){1,4}){7})`
var xForwardedForRegex = fmt.Sprintf(`^%s$`, ipv4v6Regex) // may only contain a single ip address
var forwardedRegex = fmt.Sprintf(`^for="%s";proto=http[s]?$`) // may only contain a single ip address

func readUserIP(r *http.Request) (*IpAddresses, error) {
	ipAddresses := &IpAddresses{}
	ipAddresses.RealIp = r.Header.Get("X-Real-Ip")
	ipAddresses.ForwardedFor = r.Header.Get("X-Forwarded-For")
	ipAddresses.Forwarded = r.Header.Get("Forwarded")
	ipAddresses.RemoteAddr = r.RemoteAddr
	ipAddresses.TestAddr = r.URL.Query().Get("testaddr")

	var err error
	var match bool

	match, err = regexp.MatchString(xForwardedForRegex, ipAddresses.ForwardedFor)
	if err != nil { return nil, err}
	if !match {
		return nil, fmt.Errorf("X-Forwarded-For header '%s' does not match expected pattern %s", ipAddresses.ForwardedFor, xForwardedForRegex)
	}

	match, err = regexp.MatchString(forwardedRegex, ipAddresses.Forwarded)
	if err != nil { return nil, err}
	if !match {
		return nil, fmt.Errorf("Forwarded header '%s' does not match expected pattern %s", ipAddresses.Forwarded, forwardedRegex)
	}

	return ipAddresses, nil
}
