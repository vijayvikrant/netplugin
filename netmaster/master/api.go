/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package master

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/contiv/contivmodel"
	"github.com/contiv/netplugin/netmaster/intent"
	"github.com/contiv/netplugin/netmaster/mastercfg"
	"github.com/contiv/netplugin/utils"
	"github.com/contiv/netplugin/utils/netutils"
	"github.com/contiv/objdb/modeldb"

	log "github.com/Sirupsen/logrus"
)

// AddressAllocRequest is the address request from netplugin
type AddressAllocRequest struct {
	NetworkID            string // Unique identifier for the network
	AddressPool          string // Address pool from which to allocate the address
	PreferredIPv4Address string // Preferred address
}

// AddressAllocResponse is the response from netmaster
type AddressAllocResponse struct {
	NetworkID   string // Unique identifier for the network
	IPv4Address string // Allocated address
}

// AddressReleaseRequest is the release request from netplugin
type AddressReleaseRequest struct {
	NetworkID   string // Unique identifier for the network
	IPv4Address string // Allocated address
}

// CreateNetworkRequest has the network create request from netplugin
type CreateNetworkRequest struct {
	TenantName    string               // tenant name
	NetworkName   string               // network name
	ConfigNetwork intent.ConfigNetwork // Endpoint configuration
}

// CreateNetworkResponse has the network create response from netmaster
type CreateNetworkResponse struct {
	Err error
}

// DeleteNetworkRequest has the network create request from netplugin
type DeleteNetworkRequest struct {
	TenantName  string // tenant name
	NetworkName string // network name
}

// DeleteNetworkResponse has the network create response from netmaster
type DeleteNetworkResponse struct {
	Err error
}

// CreateEndpointRequest has the endpoint create request from netplugin
type CreateEndpointRequest struct {
	TenantName  string          // tenant name
	NetworkName string          // network name
	ServiceName string          // service name
	EndpointID  string          // Unique identifier for the endpoint
	ConfigEP    intent.ConfigEP // Endpoint configuration
}

// CreateEndpointResponse has the endpoint create response from netmaster
type CreateEndpointResponse struct {
	EndpointConfig mastercfg.CfgEndpointState // Endpoint config
}

// DeleteEndpointRequest is the delete endpoint request from netplugin
type DeleteEndpointRequest struct {
	TenantName  string // tenant name
	NetworkName string // network name
	ServiceName string // service name
	EndpointID  string // Unique identifier for the endpoint
	IPv4Address string // Allocated IPv4 address for the endpoint
}

// DeleteEndpointResponse is the delete endpoint response from netmaster
type DeleteEndpointResponse struct {
	EndpointConfig mastercfg.CfgEndpointState // Endpoint config
}

// Global mutex for address allocation
var addrMutex sync.Mutex

// AllocAddressHandler allocates addresses
func AllocAddressHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var allocReq AddressAllocRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&allocReq)
	if err != nil {
		log.Errorf("Error decoding AllocAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received AddressAllocRequest: %+v", allocReq)

	// Take a global lock for address allocation
	addrMutex.Lock()
	defer addrMutex.Unlock()

	// Get hold of the state driver
	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	networkID := ""

	// Determine the network id to use
	if allocReq.NetworkID != "" {
		networkID = allocReq.NetworkID
	} else {
		// find the network from address pool
		subnetIP := strings.Split(allocReq.AddressPool, "/")[0]
		subnetLen := strings.Split(allocReq.AddressPool, "/")[1]

		// find the network from networkID
		readNet := &mastercfg.CfgNetworkState{}
		readNet.StateDriver = stateDriver
		netList, err := readNet.ReadAll()
		if err != nil {
			if !strings.Contains(err.Error(), "Key not found") {
				log.Errorf("error reading keys during host create. Error: %s", err)
				return nil, err
			}
		}

		for _, ncfg := range netList {
			nw := ncfg.(*mastercfg.CfgNetworkState)
			if nw.SubnetIP == subnetIP && fmt.Sprintf("%d", nw.SubnetLen) == subnetLen {
				networkID = nw.ID
			}
		}
	}

	if networkID == "" {
		log.Errorf("Could not find the network for: %s", allocReq.NetworkID)
		return nil, errors.New("Network not found")
	}

	// find the network from network id
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	err = nwCfg.Read(networkID)
	if err != nil {
		log.Errorf("network %s is not operational", allocReq.NetworkID)
		return nil, err
	}

	// Alloc addresses
	addr, err := networkAllocAddress(nwCfg, allocReq.PreferredIPv4Address)
	if err != nil {
		log.Errorf("Failed to allocate address. Err: %v", err)
		return nil, err
	}

	// Build the response
	aresp := AddressAllocResponse{
		NetworkID:   allocReq.NetworkID,
		IPv4Address: addr + "/" + fmt.Sprintf("%d", nwCfg.SubnetLen),
	}

	return aresp, nil
}

// ReleaseAddressHandler releases addresses
func ReleaseAddressHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var relReq AddressReleaseRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&relReq)
	if err != nil {
		log.Errorf("Error decoding ReleaseAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received AddressReleaseRequest: %+v", relReq)

	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	// find the network from network id
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	err = nwCfg.Read(relReq.NetworkID)
	if err != nil {
		log.Errorf("network %s is not operational", relReq.NetworkID)
		return nil, err
	}

	// release addresses
	err = networkReleaseAddress(nwCfg, relReq.IPv4Address)
	if err != nil {
		log.Errorf("Failed to release address. Err: %v", err)
		return nil, err
	}

	return "success", nil
}

// CreateEndpointHandler handles create endpoint requests
func CreateEndpointHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var epReq CreateEndpointRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&epReq)
	if err != nil {
		log.Errorf("Error decoding AllocAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received CreateEndpointRequest: %+v", epReq)
	// Take a global lock for address allocation
	addrMutex.Lock()
	defer addrMutex.Unlock()

	// Gte the state driver
	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	// find the network from network id
	netID := epReq.NetworkName + "." + epReq.TenantName
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	err = nwCfg.Read(netID)
	if err != nil {
		log.Errorf("network %s is not operational", netID)
		return nil, err
	}

	// Create the endpoint
	epCfg, err := CreateEndpoint(stateDriver, nwCfg, &epReq.ConfigEP)
	if err != nil {
		log.Errorf("CreateEndpoint failure for ep: %v. Err: %v", epReq.ConfigEP, err)
		return nil, err
	}

	// build ep create response
	epResp := CreateEndpointResponse{
		EndpointConfig: *epCfg,
	}

	// return the response
	return epResp, nil
}

// DeleteEndpointHandler handles delete endpoint requests
func DeleteEndpointHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var epdelReq DeleteEndpointRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&epdelReq)
	if err != nil {
		log.Errorf("Error decoding AllocAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received DeleteEndpointRequest: %+v", epdelReq)

	// Gte the state driver
	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	// Take a global lock for address release
	addrMutex.Lock()
	defer addrMutex.Unlock()

	// build the endpoint ID
	netID := epdelReq.NetworkName + "." + epdelReq.TenantName
	epID := getEpName(netID, &intent.ConfigEP{Container: epdelReq.EndpointID})

	// delete the endpoint
	epCfg, err := DeleteEndpointID(stateDriver, epID)
	if err != nil {
		log.Errorf("Error deleting endpoint: %v", epID)
		return nil, err
	}

	// build the response
	delResp := DeleteEndpointResponse{
		EndpointConfig: *epCfg,
	}

	// done. return resp
	return delResp, nil
}

// CreateNetworkHandler handles network create requests from docker/mesos etc.
func CreateNetworkHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var cnReq CreateNetworkRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&cnReq)
	if err != nil {
		log.Errorf("Error decoding AllocAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received CreateNetworkRequest: %+v", cnReq)

	tenant := contivModel.FindTenant(cnReq.TenantName)
	if tenant == nil {
		log.Errorf("Tenant not found")
		return nil, fmt.Errorf("Tenant not found")
	}

	nwCfg := cnReq.ConfigNetwork

	var network contivModel.Network
	network.Key = cnReq.TenantName + ":" + nwCfg.Name
	network.Encap = nwCfg.PktTagType
	network.Gateway = nwCfg.Gateway
	network.NetworkName = nwCfg.Name
	network.PktTag = nwCfg.PktTag
	network.Subnet = nwCfg.SubnetCIDR
	network.TenantName = cnReq.TenantName

	// Make a request to contivModel to create the network in the state store
	path := "http://localhost:9999/api/network_event/" + cnReq.TenantName + ":" + nwCfg.Name + "/"
	err = netutils.HTTPPost(path, &network)
	if err != nil {
		log.Errorf("master failed to delete endpoint. Err:%v", err)
		return nil, err
	}

	// Setup links
	modeldb.AddLink(&network.Links.Tenant, tenant)
	modeldb.AddLinkSet(&tenant.LinkSets.Networks, &network)

	err = network.Write()
	if err != nil {
		log.Errorf("CreateNetwork error for: %+v Err: %v", network, err)
		return nil, err
	}

	// Save the tenant too since we added the links
	err = tenant.Write()
	if err != nil {
		log.Errorf("Error updating tenant state(%+v). Err: %v", tenant, err)
		return nil, err
	}

	// Gte the state driver
	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	// Create the network
	// The below needs an another option to skip sending a network create back to docker
	err = CreateNetwork(cnReq.ConfigNetwork, stateDriver, cnReq.TenantName, false)
	if err != nil {
		log.Errorf("Error creating network {%+v}. Err: %v", cnReq.ConfigNetwork, err)
		return nil, err
	}

	netResp := CreateNetworkResponse{
		Err: err,
	}

	return netResp, nil
}

// DeleteNetworkHandler handles network delete requests from docker/mesos etc.
func DeleteNetworkHandler(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	var dnReq DeleteNetworkRequest

	// Get object from the request
	err := json.NewDecoder(r.Body).Decode(&dnReq)
	if err != nil {
		log.Errorf("Error decoding AllocAddressHandler. Err %v", err)
		return nil, err
	}

	log.Infof("Received DeleteNetworkRequest: %+v", dnReq)

	tenant := contivModel.FindTenant(dnReq.TenantName)
	if tenant == nil {
		log.Errorf("Tenant not found")
		return nil, fmt.Errorf("Tenant not found")
	}

	// TODO
	// RemoveLinkSet for the network

	// Gte the state driver
	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		return nil, err
	}

	// Create the network
	// The below needs an another option to skip sending a network create back to docker
	err = DeleteNetworkID(stateDriver, dnReq.NetworkName+"."+dnReq.TenantName, false)
	if err != nil {
		log.Errorf("Error deleting network {%+v}. Err: %v", dnReq, err)
		return nil, err
	}

	// Make a request to contivModel to create the network in the state store
	path := "http://localhost:9999/api/network_event/" + dnReq.TenantName + ":" + dnReq.NetworkName + "/"
	err = netutils.HTTPDelete(path)
	if err != nil {
		log.Errorf("master failed to delete endpoint. Err:%v", err)
		return nil, err
	}

	netResp := DeleteNetworkResponse{
		Err: err,
	}

	return netResp, nil
}
