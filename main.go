// Copyright 2019 Google LLC
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

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

type IpAddresses struct {
	RealIp string
	ForwardedFor string
	RemoteAddr string
	TestAddr string
}

// function to make printing IpAddresses nicer
func (ipAddresses *IpAddresses) String() string {
	return fmt.Sprintf("Real IP: %s, Forwarded For: %s, Remote Addr: %s, Test Addr: %s", ipAddresses.RealIp, ipAddresses.ForwardedFor, ipAddresses.RemoteAddr, ipAddresses.TestAddr)
}

func main() {

	allowedIPsEnvVar := os.Getenv("ALLOWED_IPS")
	if allowedIPsEnvVar == "" {
		allowedIPsEnvVar = "123.123.123.123:abc=def&ghi=jkl,127.0.0.1:def=2"
	}
fmt.Printf("Config: %v\n", allowedIPsEnvVar)

	model := make(map[string]map[string]string)
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		userIPs := readUserIP(r)
		w.Header().Add("X-Real-IP", userIPs.RealIp)
		w.Header().Add("X-Forwarded-For", userIPs.ForwardedFor)
		w.Header().Add("X-Remote-Addr", userIPs.RemoteAddr)
		w.Header().Add("X-Test-Addr", userIPs.RemoteAddr)
		fmt.Printf("Request to URL %s from %s\n", r.URL, userIPs)
		if r.Method == http.MethodGet {
			keyname := r.URL.Query().Get("keyname")
			tokens := model[userIPs.RealIp]
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
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("E1000"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Handling HTTP requests on %s.", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func readUserIP(r *http.Request) *IpAddresses {
	ipAddresses := &IpAddresses{}
	ipAddresses.RealIp = r.Header.Get("X-Real-Ip")
	ipAddresses.ForwardedFor = r.Header.Get("X-Forwarded-For")
	ipAddresses.RemoteAddr = r.RemoteAddr
	ipAddresses.TestAddr = r.URL.Query().Get("testaddr")
    return ipAddresses
}
