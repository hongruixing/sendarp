package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var interfacename = "ens33"

func main() {

	var wg sync.WaitGroup

	wg.Add(1)
	// Start up a scan on each interface.
	go func() {
		defer wg.Done()
		if err := scan(); err != nil {
			log.Printf("interface %v: %v", interfacename, err)
		}
	}()

	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan() error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	_, addr, err := net.ParseCIDR("192.168.4.3/24")
	if err != nil {
		log.Fatal(err)
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(interfacename, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, stop)
	defer close(stop)
	for {
		// Write our scan packets out to the handle.
		if err := writeARP(handle, addr); err != nil {
			log.Printf("error writing packets on %v: %v", interfacename, err)
			return err
		}
		// We don't know exactly how long it'll take for packets to be
		// sent back to us, but 10 seconds should be more than enough
		// time ;)
		time.Sleep(10 * time.Second)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, stop chan struct{}) {
	//hwAddr, _ := net.ParseMAC(macadress)
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, addr *net.IPNet) error {
	hwAddr := getMacAddress(interfacename)
	hostip := "192.168.4.3/24"
	_, ipn, err := net.ParseCIDR(hostip)
	if err != nil {
		fmt.Println("Error", hostip, err)

	}
	fmt.Println("Error", ipn, ipn.IP)
	host := net.ParseIP("192.168.4.3").To4()
	fmt.Println("Error", host)
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       hwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(hwAddr),
		SourceProtAddress: []byte(host),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		ret := gopacket.NewPacket(
			buf.Bytes(),
			layers.LayerTypeEthernet,
			gopacket.Default,
		)
		tagpkt, err := PushVLAN(ret, 40)
		if err != nil {
			return err
		}
		err = handle.WritePacketData(tagpkt.Data())
		if err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}
func getEthernetLayer(pkt gopacket.Packet) *layers.Ethernet {
	eth := &layers.Ethernet{}
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ = ethLayer.(*layers.Ethernet)
	}
	return eth
}

// PushVLAN pushes the vlan header to the packet and returns tha packet
func PushVLAN(pkt gopacket.Packet, vid uint16) (gopacket.Packet, error) {
	if eth := getEthernetLayer(pkt); eth != nil {
		ethernetLayer := &layers.Ethernet{
			SrcMAC:       eth.SrcMAC,
			DstMAC:       eth.DstMAC,
			EthernetType: 0x8100,
		}
		dot1qLayer := &layers.Dot1Q{
			Type:           eth.EthernetType,
			VLANIdentifier: uint16(vid),
		}

		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(
			buffer,
			gopacket.SerializeOptions{
				FixLengths: false,
			},
			ethernetLayer,
			dot1qLayer,
			gopacket.Payload(eth.Payload),
		)
		ret := gopacket.NewPacket(
			buffer.Bytes(),
			layers.LayerTypeEthernet,
			gopacket.Default,
		)
		log.Printf("Push the 802.1Q header (VID: %d)", vid)
		return ret, nil
	}
	return nil, errors.New("failed to push vlan")
}
func getMacAddress(ifName string) net.HardwareAddr {
	var err error
	var netIf *net.Interface
	var hwAddr net.HardwareAddr
	if netIf, err = net.InterfaceByName(ifName); err == nil {
		hwAddr = netIf.HardwareAddr
	}
	return hwAddr
}
