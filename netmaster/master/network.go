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
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/contiv/netplugin/core"
	"github.com/contiv/netplugin/netmaster/docknet"
	"github.com/contiv/netplugin/netmaster/gstate"
	"github.com/contiv/netplugin/netmaster/intent"
	"github.com/contiv/netplugin/netmaster/mastercfg"
	"github.com/contiv/netplugin/utils"
	"github.com/contiv/netplugin/utils/netutils"

	log "github.com/Sirupsen/logrus"
)

func checkPktTagType(pktTagType string) error {
	if pktTagType != "" && pktTagType != "vlan" && pktTagType != "vxlan" {
		return core.Errorf("invalid pktTagType")
	}

	return nil
}

func validateNetworkConfig(tenant *intent.ConfigTenant) error {
	var err error

	if tenant.Name == "" {
		return core.Errorf("null tenant name")
	}

	for _, network := range tenant.Networks {
		if network.Name == "" {
			core.Errorf("null network name")
		}

		err = checkPktTagType(network.PktTagType)
		if err != nil {
			return err
		}

		if network.SubnetCIDR != "" {
			_, _, err = netutils.ParseCIDR(network.SubnetCIDR)
			if err != nil {
				return err
			}
		}

		if network.Gateway != "" {
			if net.ParseIP(network.Gateway) == nil {
				return core.Errorf("invalid IP")
			}
		}
	}

	return err
}

// CreateNetwork creates a network from intent
func CreateNetwork(network intent.ConfigNetwork, stateDriver core.StateDriver, tenantName string, netctlTriggered bool) error {
	var extPktTag, pktTag uint

	gCfg := gstate.Cfg{}
	gCfg.StateDriver = stateDriver
	err := gCfg.Read("")
	if err != nil {
		log.Errorf("error reading tenant cfg state. Error: %s", err)
		return err
	}

	// Create network state
	networkID := network.Name + "." + tenantName
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	if nwCfg.Read(networkID) == nil {
		// TODO: check if parameters changed and apply an update if needed
		return nil
	}

	subnetIP, subnetLen, _ := netutils.ParseCIDR(network.SubnetCIDR)

	// construct and update network state
	nwCfg = &mastercfg.CfgNetworkState{
		Tenant:      tenantName,
		NetworkName: network.Name,
		PktTagType:  network.PktTagType,
		SubnetIP:    subnetIP,
		SubnetLen:   subnetLen,
		Gateway:     network.Gateway,
	}

	nwCfg.ID = networkID
	nwCfg.StateDriver = stateDriver

	// Allocate pkt tags
	reqPktTag := uint(network.PktTag)
	if nwCfg.PktTagType == "vlan" {
		pktTag, err = gCfg.AllocVLAN(reqPktTag)
		if err != nil {
			return err
		}
	} else if nwCfg.PktTagType == "vxlan" {
		extPktTag, pktTag, err = gCfg.AllocVXLAN(reqPktTag)
		if err != nil {
			return err
		}
	}

	nwCfg.ExtPktTag = int(extPktTag)
	nwCfg.PktTag = int(pktTag)

	// Reserve gateway IP address
	ipAddrValue, err := netutils.GetIPNumber(nwCfg.SubnetIP, nwCfg.SubnetLen, 32, nwCfg.Gateway)
	if err != nil {
		log.Errorf("Error parsing gateway address %s. Err: %v", nwCfg.Gateway, err)
		return err
	}
	nwCfg.IPAllocMap.Set(ipAddrValue)

	netutils.InitSubnetBitset(&nwCfg.IPAllocMap, nwCfg.SubnetLen)
	err = nwCfg.Write()
	if err != nil {
		return err
	}

	if GetClusterMode() == "docker" {
		if netctlTriggered {
			// Create the network in docker
			err = docknet.CreateDockNet(tenantName, network.Name, "", nwCfg)
			if err != nil {
				log.Errorf("Error creating network %s in docker. Err: %v", nwCfg.ID, err)
				return err
			}

			// Attach service container endpoint to the network
			err = attachServiceContainer(tenantName, network.Name, stateDriver)
			if err != nil {
				log.Errorf("Error attaching service container to network: %s. Err: %v",
					networkID, err)
				return err
			}
		}
	}

	return nil
}

func attachServiceContainer(tenantName, networkName string, stateDriver core.StateDriver) error {
	contName := tenantName + "dns"
	docker, err := utils.GetDockerClient()
	if err != nil {
		log.Errorf("Unable to connect to docker. Error %v", err)
		return err
	}

	// Trim default tenant
	dnetName := docknet.GetDocknetName(tenantName, networkName, "")

	err = docker.ConnectNetwork(dnetName, contName)
	if err != nil {
		log.Errorf("Could not attach container(%s) to network %s. Error: %s",
			contName, dnetName, err)
		return fmt.Errorf("Could not attach container(%s) to network %s."+
			"Please make sure %s container is up.",
			contName, dnetName, contName)
	}

	// inspect the container
	cinfo, err := docker.InspectContainer(contName)
	if err != nil {
		log.Errorf("Error inspecting the container %s. Err: %v", contName, err)
		return err
	}

	log.Debugf("Container info: %+v\n Hostconfig: %+v", cinfo, cinfo.HostConfig)

	ninfo, err := docker.InspectNetwork(dnetName)
	if err != nil {
		log.Errorf("Error getting network info for %s. Err: %v", dnetName, err)
		return err
	}

	log.Debugf("Network info: %+v", ninfo)

	// find the container in network info
	epInfo, ok := ninfo.Containers[cinfo.Id]
	if !ok {
		log.Errorf("Could not find container %s in network info", cinfo.Id)
		return errors.New("Endpoint not found")
	}

	// read network Config
	nwCfg := &mastercfg.CfgNetworkState{}
	networkID := networkName + "." + tenantName
	nwCfg.StateDriver = stateDriver
	err = nwCfg.Read(networkID)
	if err != nil {
		return err
	}

	// set the dns server Info
	nwCfg.DNSServer = strings.Split(epInfo.IPv4Address, "/")[0]
	log.Infof("Dns server for network %s: %s", networkName, nwCfg.DNSServer)

	// write the network config
	err = nwCfg.Write()
	if err != nil {
		return err
	}

	return nil
}

// detachServiceContainer detaches the service container's endpoint during network delete
//      - detach happens only if all other endpoints in the network are already removed
func detachServiceContainer(tenantName, networkName string) error {
	docker, err := utils.GetDockerClient()
	if err != nil {
		log.Errorf("Unable to connect to docker. Error %v", err)
		return errors.New("Unable to connect to docker")
	}

	dnsContName := tenantName + "dns"
	cinfo, err := docker.InspectContainer(dnsContName)
	if err != nil {
		log.Errorf("Error inspecting the container %s. Err: %v", dnsContName, err)
		return err
	}

	// Trim default tenant
	dnetName := docknet.GetDocknetName(tenantName, networkName, "")

	// inspect docker network
	nwState, err := docker.InspectNetwork(dnetName)
	if err != nil {
		log.Errorf("Error while inspecting network: %+v", dnetName)
		return err
	}

	log.Infof("Containers in network: %+v are {%+v}", dnetName, nwState.Containers)
	dnsServerIP := strings.Split(nwState.Containers[cinfo.Id].IPv4Address, "/")[0]

	stateDriver, err := utils.GetStateDriver()
	if err != nil {
		log.Errorf("Could not get StateDriver while trying to disconnect dnsContainer from %+v", networkName)
		return err
	}

	// Read network config and get DNSServer information
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	networkID := networkName + "." + tenantName
	err = nwCfg.Read(networkID)
	if err != nil {
		return err
	}

	log.Infof("dnsServerIP: %+v, nwCfg.dnsip: %+v", dnsServerIP, nwCfg.DNSServer)
	// Remove dns container from network if all other endpoints are withdrawn
	if len(nwState.Containers) == 1 && (dnsServerIP == nwCfg.DNSServer) {
		log.Infof("Disconnecting dns container from network as all other endpoints are removed: %+v", networkName)
		err = docker.DisconnectNetwork(dnetName, dnsContName, false)
		if err != nil {
			log.Errorf("Could not detach container(%s) from network %s. Error: %s",
				dnsContName, dnetName, err)
			return err
		}
	}

	return nil
}

// CreateNetworks creates the necessary virtual networks for the tenant
// provided by ConfigTenant.
func CreateNetworks(stateDriver core.StateDriver, tenant *intent.ConfigTenant) error {
	// Validate the config
	err := validateNetworkConfig(tenant)
	if err != nil {
		log.Errorf("error validating network config. Error: %s", err)
		return err
	}

	for _, network := range tenant.Networks {
		err = CreateNetwork(network, stateDriver, tenant.Name, true)
		if err != nil {
			log.Errorf("Error creating network {%+v}. Err: %v", network, err)
			return err
		}
	}

	return err
}

func freeNetworkResources(stateDriver core.StateDriver, nwCfg *mastercfg.CfgNetworkState, gCfg *gstate.Cfg) (err error) {
	if nwCfg.PktTagType == "vlan" {
		err = gCfg.FreeVLAN(uint(nwCfg.PktTag))
		if err != nil {
			return err
		}
	} else if nwCfg.PktTagType == "vxlan" {
		log.Infof("freeing vlan %d vxlan %d", nwCfg.PktTag, nwCfg.ExtPktTag)
		err = gCfg.FreeVXLAN(uint(nwCfg.ExtPktTag), uint(nwCfg.PktTag))
		if err != nil {
			return err
		}
	}

	if err := gCfg.UnassignNetwork(nwCfg.ID); err != nil {
		return err
	}

	return err
}

// DeleteNetworkID removes a network by ID.
func DeleteNetworkID(stateDriver core.StateDriver, netID string, netctlTriggered bool) error {
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	err := nwCfg.Read(netID)
	if err != nil {
		log.Errorf("network %s is not operational", netID)
		return err
	}

	if GetClusterMode() == "docker" {
		// detach Dns container
		err = detachServiceContainer(nwCfg.Tenant, nwCfg.NetworkName)
		if err != nil {
			log.Errorf("Error detaching service container. Err: %v", err)
		}

		if netctlTriggered {
			// Delete the docker network
			err = docknet.DeleteDockNet(nwCfg.Tenant, nwCfg.NetworkName, "")
			if err != nil {
				log.Errorf("Error deleting network %s. Err: %v", netID, err)
			}
		}
	}

	gCfg := &gstate.Cfg{}
	gCfg.StateDriver = stateDriver
	err = gCfg.Read("")
	if err != nil {
		log.Errorf("error reading tenant info for %q. Error: %s", nwCfg.Tenant, err)
		return err
	}

	// Free resource associated with the network
	err = freeNetworkResources(stateDriver, nwCfg, gCfg)
	if err != nil {
		return err
	}

	err = nwCfg.Clear()
	if err != nil {
		log.Errorf("error writing nw config. Error: %s", err)
		return err
	}

	return err
}

// DeleteNetworks removes all the virtual networks for a given tenant.
func DeleteNetworks(stateDriver core.StateDriver, tenant *intent.ConfigTenant) error {
	gCfg := &gstate.Cfg{}
	gCfg.StateDriver = stateDriver

	err := gCfg.Read("")
	if err != nil {
		log.Errorf("error reading tenant state. Error: %s", err)
		return err
	}

	err = validateNetworkConfig(tenant)
	if err != nil {
		log.Errorf("error validating network config. Error: %s", err)
		return err
	}

	for _, network := range tenant.Networks {
		if len(network.Endpoints) > 0 {
			continue
		}

		networkID := network.Name + "." + tenant.Name
		nwCfg := &mastercfg.CfgNetworkState{}
		nwCfg.StateDriver = stateDriver
		err = nwCfg.Read(networkID)
		if err != nil {
			log.Infof("network %q is not operational", network.Name)
			continue
		}

		err = freeNetworkResources(stateDriver, nwCfg, gCfg)
		if err != nil {
			return err
		}

		err = nwCfg.Clear()
		if err != nil {
			log.Errorf("error when writing nw config. Error: %s", err)
			return err
		}
	}

	return err
}

// Allocate an address from the network
func networkAllocAddress(nwCfg *mastercfg.CfgNetworkState, reqAddr string) (string, error) {
	var ipAddress string
	var ipAddrValue uint
	var found bool
	var err error

	// alloc address
	if reqAddr == "" {
		ipAddrValue, found = nwCfg.IPAllocMap.NextClear(0)
		if !found {
			log.Errorf("auto allocation failed - address exhaustion in subnet %s/%d",
				nwCfg.SubnetIP, nwCfg.SubnetLen)
			err = core.Errorf("auto allocation failed - address exhaustion in subnet %s/%d",
				nwCfg.SubnetIP, nwCfg.SubnetLen)
			return "", err
		}

		ipAddress, err = netutils.GetSubnetIP(nwCfg.SubnetIP, nwCfg.SubnetLen, 32, ipAddrValue)
		if err != nil {
			log.Errorf("create eps: error acquiring subnet ip. Error: %s", err)
			return "", err
		}
	} else if reqAddr != "" && nwCfg.SubnetIP != "" {
		ipAddrValue, err = netutils.GetIPNumber(nwCfg.SubnetIP, nwCfg.SubnetLen, 32, reqAddr)
		if err != nil {
			log.Errorf("create eps: error getting host id from hostIP %s Subnet %s/%d. Error: %s",
				reqAddr, nwCfg.SubnetIP, nwCfg.SubnetLen, err)
			return "", err
		}

		ipAddress = reqAddr
	}

	// Set the bitmap
	nwCfg.IPAllocMap.Set(ipAddrValue)

	err = nwCfg.Write()
	if err != nil {
		log.Errorf("error writing nw config. Error: %s", err)
		return "", err
	}

	return ipAddress, nil
}

// networkReleaseAddress release the ip address
func networkReleaseAddress(nwCfg *mastercfg.CfgNetworkState, ipAddress string) error {
	ipAddrValue, err := netutils.GetIPNumber(nwCfg.SubnetIP, nwCfg.SubnetLen, 32, ipAddress)
	if err != nil {
		log.Errorf("error getting host id from hostIP %s Subnet %s/%d. Error: %s",
			ipAddress, nwCfg.SubnetIP, nwCfg.SubnetLen, err)
		return err
	}

	nwCfg.IPAllocMap.Clear(ipAddrValue)
	nwCfg.EpCount--

	return nil
}
