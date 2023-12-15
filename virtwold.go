//
// Virtual Wake-on-LAN
//
// Listens for a WOL magic packet (UDP), then connects to the local libvirt socket and finds a matching VM
// If a matching VM is found, it is started (if not already running)
//
// Assumes the VM has a static MAC configured
// Assumes libvirtd connection is at /var/run/libvirt/libvirt-sock
//
// Filters on len=102 and len=144 (WOL packet) and len=234 (WOL packet with password)

package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"libvirt.org/go/libvirt"
	"libvirt.org/go/libvirtxml"
	"log"
)

func main() {
	var iface string                                                         // Interface we'll listen on
	var buffer = int32(1600)                                                 // Buffer for packets received
	var filter = "udp and broadcast and (len = 102 or len = 144 or len=234)" // PCAP filter to catch UDP WOL packets

	flag.StringVar(&iface, "interface", "", "Network interface name to listen on")
	flag.Parse()

	if !deviceExists(iface) {
		log.Fatalf("Unable to open device: %s", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open device: %v", err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatalf("Something in the BPF went wrong!: %v", err)
	}

	// Handle every packet received, looping forever
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		// Called for each packet received
		fmt.Printf("Received WOL packet, ")
		mac, err := GrabMACAddr(packet)
		if err != nil {
			log.Fatalf("Error with packet: %v", err)
		}
		WakeVirtualMachine(mac)
	}
}

// Return the first MAC address seen in the WOL packet
func GrabMACAddr(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", payload[12], payload[13], payload[14], payload[15], payload[16], payload[17])
		fmt.Printf("found MAC: %s\n", mac)
		return mac, nil
	}
	return "", errors.New("no MAC found in packet")
}

func WakeVirtualMachine(mac string) bool {
	// Connect to the local libvirt socket
	connection, err := libvirt.NewConnect("qemu+tcp:///system")
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer connection.Close()

	// Get a list of all inactive VMs (aka Domains) configured so we can loop through them
	domains, err := connection.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_INACTIVE)
	if err != nil {
		log.Fatalf("failed to retrieve domains: %v", err)
	}

	for _, domain := range domains {
		// Now we get the XML Description for each domain
		xmldesc, err := domain.GetXMLDesc(0)
		if err != nil {
			log.Fatalf("failed retrieving XML: %v", err)
		}

		// Get the details for each domain
		domcfg := &libvirtxml.Domain{}
		err = domcfg.Unmarshal(xmldesc)
		if err != nil {
			log.Fatalf("failed retrieving domain configuration: %v", err)
		}

		// Loop through each interface found
		for _, iface := range domcfg.Devices.Interfaces {
			domainmac := iface.MAC.Address

			if domainmac == mac {
				// We'll use the name later, so may as well get it here
				name := domcfg.Name

				// Get the state of the VM and take action
				state, _, err := domain.GetState()
				if err != nil {
					log.Fatalf("failed to check domain state: %v", err)
				}

				// Print an informative message about the state of things
				switch state {
				case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF, libvirt.DOMAIN_CRASHED:
					fmt.Printf("Waking system: %s at MAC %s\n", name, mac)

				case libvirt.DOMAIN_PMSUSPENDED:
					fmt.Printf("Unsuspending system: %s at MAC %s\n", name, mac)

				case libvirt.DOMAIN_PAUSED:
					fmt.Printf("Resuming system: %s at MAC %s\n", name, mac)

				default:
				}

				// Try and start the VM
				err = domain.Create()
				if err != nil {
					fmt.Printf("System is already running or in a state that cannot be woken from. State: %d\n", state)
				}
			}
		}
	}

	return true
}

// Check if the network device exists
func deviceExists(interfacename string) bool {
	if interfacename == "" {
		fmt.Printf("No interface to listen on specified\n\n")
		flag.PrintDefaults()
		return false
	}
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Name == interfacename {
			return true
		}
	}
	return false
}
