//
// Virtual Wake-on-LAN
//
// Listens for a WOL magic packet (UDP), then connects to libvirt and finds a matching inactive VM
// If a matching VM is found and is not running, it is started
//
// Assumes the VM has a static MAC configured
// Uses configurable libvirt URI (default: qemu+tcp:///system)
//
// Filters on len=102 and len=144 (WOL packet) and len=234 (WOL packet with password)

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"libvirt.org/go/libvirt"
	"libvirt.org/go/libvirtxml"
)

const (
	// WOL packet structure
	wolHeaderSize = 6                                            // 6 bytes of 0xFF
	wolMACSize    = 6                                            // MAC address is 6 bytes
	wolMACRepeats = 16                                           // MAC repeated 16 times
	wolMinSize    = wolHeaderSize + (wolMACSize * wolMACRepeats) // 102 bytes minimum
)

func main() {
	var iface string        // Interface we'll listen on
	var libvirturi string   // URI to the libvirt daemon
	var buffer = int32(160) // Small buffer for WOL packets with headers
	// Optimized BPF filter: UDP port 9 (standard WOL port), reasonable packet size
	// Note: 'greater' checks total packet length (headers + payload), not just UDP payload
	var filter = "udp and dst port 9 and greater 100"

	flag.StringVar(&iface, "interface", "eth0", "Network interface name to listen on")
	flag.StringVar(&libvirturi, "libvirturi", "qemu+tcp:///system", "URI to libvirt daemon, such as qemu:///system")
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
	log.Printf("Listening for WOL packets on %s (libvirt URI: %s)", iface, libvirturi)
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		// Called for each packet received
		log.Printf("Received potential WOL packet")
		mac, err := GrabMACAddr(packet)
		if err != nil {
			log.Printf("Warning: Error parsing packet: %v", err)
			continue
		}
		if err := WakeVirtualMachine(mac, libvirturi); err != nil {
			log.Printf("Error waking virtual machine: %v", err)
		}
	}
}

// Extract and validate MAC address from WOL magic packet
// WOL packet structure: 6 bytes of 0xFF + MAC repeated 16 times + optional password
func GrabMACAddr(packet gopacket.Packet) (string, error) {
	app := packet.ApplicationLayer()
	if app == nil {
		return "", errors.New("no application layer found in packet")
	}

	payload := app.Payload()
	if len(payload) < wolMinSize {
		return "", fmt.Errorf("payload too short: got %d bytes, need at least %d", len(payload), wolMinSize)
	}

	// Validate sync stream: first 6 bytes must be 0xFF
	for i := 0; i < wolHeaderSize; i++ {
		if payload[i] != 0xFF {
			return "", fmt.Errorf("invalid WOL header: byte %d is 0x%02x, expected 0xFF", i, payload[i])
		}
	}

	// Extract MAC from first repetition (bytes 6-11)
	macOffset := wolHeaderSize
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		payload[macOffset], payload[macOffset+1], payload[macOffset+2],
		payload[macOffset+3], payload[macOffset+4], payload[macOffset+5])
	log.Printf("Validated WOL packet for MAC: %s", mac)
	return mac, nil
}

func WakeVirtualMachine(mac string, libvirturi string) error {
	// Connect to the local libvirt socket
	connection, err := libvirt.NewConnect(libvirturi)
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer connection.Close()

	// Get a list of all inactive VMs (aka Domains) configured so we can loop through them
	domains, err := connection.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_INACTIVE)
	if err != nil {
		return fmt.Errorf("failed to retrieve domains: %w", err)
	}

	for _, domain := range domains {
		// Now we get the XML Description for each domain
		xmldesc, err := domain.GetXMLDesc(0)
		if err != nil {
			log.Printf("Warning: Failed retrieving XML for domain: %v", err)
			continue
		}

		// Get the details for each domain
		domcfg := &libvirtxml.Domain{}
		err = domcfg.Unmarshal(xmldesc)
		if err != nil {
			log.Printf("Warning: Failed parsing domain configuration: %v", err)
			continue
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
					log.Printf("Warning: Failed to check domain state for %s: %v", name, err)
					continue
				}

				// Print an informative message about the state of things
				switch state {
				case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF, libvirt.DOMAIN_CRASHED:
					log.Printf("Waking system: %s at MAC %s", name, mac)

				case libvirt.DOMAIN_PMSUSPENDED:
					log.Printf("Unsuspending system: %s at MAC %s", name, mac)

				case libvirt.DOMAIN_PAUSED:
					log.Printf("Resuming system: %s at MAC %s", name, mac)

				default:
					log.Printf("System %s at MAC %s is already running (state: %d)", name, mac, state)
					return nil
				}

				// Try and start the VM
				err = domain.Create()
				if err != nil {
					return fmt.Errorf("failed to start domain %s: %w", name, err)
				}
				log.Printf("Successfully started domain: %s", name)
				return nil
			}
		}
	}

	return fmt.Errorf("no inactive domain found with MAC address: %s", mac)
}

// Check if the network device exists
func deviceExists(interfacename string) bool {
	if interfacename == "" {
		log.Println("Error: No interface to listen on specified")
		flag.PrintDefaults()
		return false
	}
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Printf("Error: Failed to find network devices: %v", err)
		return false
	}

	for _, device := range devices {
		if device.Name == interfacename {
			return true
		}
	}
	return false
}
