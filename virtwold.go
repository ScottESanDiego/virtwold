//
// Virtual Wake-on-LAN
//
// Listens for a WOL magic packet (UDP), then connects to the local libvirt socket and finds a matching VM
// If a matching VM is found, it is started (if not already running)
//
// Assumes the VM has a static MAC configured
// Assumes libvirtd connection is at /var/run/libvirt/libvirt-sock
//
// Filters on len=144 (WOL packet) and len=234 (WOL packet with password)

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/digitalocean/go-libvirt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var iface string                                            // Interface we'll listen on
	var buffer = int32(1600)                                    // Buffer for packets received
	var filter = "udp and broadcast and (len = 144 or len=234)" // PCAP filter to catch UDP WOL packets

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
	c, err := net.DialTimeout("unix", "/var/run/libvirt/libvirt-sock", 2*time.Second)
	if err != nil {
		log.Fatalf("failed to dial libvirt: %v", err)
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	// Get a list of all VMs (aka Domains) configured so we can loop through them
	flags := libvirt.ConnectListDomainsActive | libvirt.ConnectListDomainsInactive
	domains, _, err := l.ConnectListAllDomains(1, flags)
	if err != nil {
		log.Fatalf("failed to retrieve domains: %v", err)
	}

	for _, d := range domains {
		//fmt.Printf("%d\t%s\t%x\n", d.ID, d.Name, d.UUID)

		// Now we get the XML Description for each domain
		xmldesc, err := l.DomainGetXMLDesc(d, 0)
		if err != nil {
			log.Fatalf("failed retrieving interfaces: %v", err)
		}

		// Feed the XML output into xmlquery
		querydoc, err := xmlquery.Parse(strings.NewReader(xmldesc))
		if err != nil {
			log.Fatalf("Failed to parse XML: %v", err)
		}

		// Perform an xmlquery to look for the MAC address in the XML
		for _, list := range xmlquery.Find(querydoc, "//domain/devices/interface/mac/@address") {
			// Use the strings.EqualFold function to do a case-insensitive comparison of MACs
			if strings.EqualFold(list.InnerText(), mac) {
				stateInt, _, err := l.DomainGetState(d, 0)
				if err != nil {
					log.Fatalf("failed to check domain state: %v", err)
				}

				state := libvirt.DomainState(stateInt)
				// fmt.Printf("Domain state is %v\n", state)

				switch state {
				case libvirt.DomainShutoff, libvirt.DomainCrashed:
					fmt.Printf("Waking system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainCreate(d); err != nil {
						log.Fatalf("Failed to start domain: %v", err)
					}
				case libvirt.DomainPmsuspended:
					fmt.Printf("PM Wakeup system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainPmWakeup(d, 0); err != nil {
						log.Fatalf("Failed to pm wakeup domain: %v", err)
					}
				case libvirt.DomainPaused:
					fmt.Printf("Resume system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainResume(d); err != nil {
						log.Fatalf("Failed to resume domain: %v", err)
					}
			        default:
					fmt.Printf("System %s is in a state that cannot be woken up. State: %d", d.Name, state)
				}
			}
		}
	}

	if err := l.Disconnect(); err != nil {
		log.Fatalf("failed to disconnect: %v", err)
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
