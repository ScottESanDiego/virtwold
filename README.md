# virtwold
Wake-on-LAN for libvirt based VMs

## Introduction
This is a daemon which listens for wake-on-LAN ("WOL") packets, and upon spotting one, tries to start the virtual machine with the associated MAC address.

One use-case (my use case) is to have a gaming VM that doesn't need to be running all the time.  NVIDIA Gamestream and Moonlight both have the ability to send WOL packets in an attempt to wake an associated system.  For "real" hardware, this works great.  Unfortunately, for VMs it doesn't really do anything since there's no physical NIC snooping for the WOL packet.  This daemon attempts to solve that.

## Mechanics
When started, this daemon will use `libpcap` to make a listener on the specified network interface, listening for packets that look like they might be wake-on-lan.  Due to how `pcap` works, the current filter is for UDP sent to the broadcast address with a length of 234 bytes (the size of a WOL packet w/security).  This seems to generate very low false-positives, doesn't require the NIC to be in promiscuous mode, and overall seems like a decent filter.

Upon receipt of a (probable) WOL packet, the daemon extracts the first MAC address (WOL packets are supposed to repeat the target machine MAC a few times).

With a MAC address in-hand, the program then connects to the local `libvirt` daemon via `/var/run/libvirt/libvirt-sock`, and gets an XML formatted list of every Virtual Machine configured (yuck).  An XML query to list all of the MAC addresses in the configured VMs, and compares that with the MAC from the WOL packet.  If a match is found, and the VM isn't already running, the daemon asks `libvirtd` to start the associated VM.

## Usage
Usage is pretty staightforward, as the command only needs one argument: the name of the network interface to listen on.  Specify this with the `--interface` flag (e.g., `--interface enp44s0`).

The daemon will keep running until killed with a SIGINT (`^c`).

Because this daemon, and wake-on-LAN, operate by MAC addresses, any VMs that are a candidate to be woken must have a hard-coded MAC in their machine configuration.

## System Integration

### systemd example service
There's a systemd service template example in `init-scripts/virtwold@.service` that should make it easy to configure for any interfaces that you need to run on

## OpenRC example init script
Systems which use openrc can find an example init script and associated conf file in `init-scripts/openrc`.  The interface should be adjusted to match your particular needs (e.g., swap `eth0` for `enp44s0` or something like that).

## Gentoo ebuild
An ebuild for Gentoo systems is available in [here](https://github.com/ScottESanDiego/scotterepo/tree/main/app-emulation/virtwold), although it only installs OpenRC init files (since that's what I use).

