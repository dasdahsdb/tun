package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

func createTUN(name string) (*os.File, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	var ifr [18]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = IFF_TUN | IFF_NO_PI

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return nil, fmt.Errorf("ioctl failed: %v", errno)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func main() {
	tun, err := createTUN("tun0")
	if err != nil {
		log.Fatalf("Error creating TUN interface: %v", err)
	}
	defer tun.Close()

	fmt.Println("TUN interface created:", tun.Name())

	buffer := make([]byte, 1500)
	for {
		n, err := tun.Read(buffer)
		if err != nil {
			log.Fatalf("Error reading from TUN interface: %v", err)
		}
		fmt.Printf("Read %d bytes: % x\n", n, buffer[:n])
		parseIPPacket(buffer[:n])
	}
}

func parseIPPacket(packet []byte) {
	if len(packet) < 20 {
		fmt.Println("Packet too short to be an IP packet")
		return
	}

	// Parse IP header
	version := packet[0] >> 4
	ihl := packet[0] & 0x0F
	length := int(packet[2])<<8 | int(packet[3])
	protocol := packet[9]
	srcIP := packet[12:16]
	dstIP := packet[16:20]

	fmt.Printf("IP Packet - Version: %d, IHL: %d, Length: %d, Protocol: %d\n", version, ihl, length, protocol)
	fmt.Printf("Source IP: %d.%d.%d.%d\n", srcIP[0], srcIP[1], srcIP[2], srcIP[3])
	fmt.Printf("Destination IP: %d.%d.%d.%d\n", dstIP[0], dstIP[1], dstIP[2], dstIP[3])

	if protocol == 6 && len(packet) >= int(ihl)*4+20 {
		parseTCPPacket(packet[int(ihl)*4:])
	} else if protocol == 17 && len(packet) >= int(ihl)*4+8 {
		parseUDPPacket(packet[int(ihl)*4:])
	} else {
		fmt.Println("Unsupported protocol or packet too short")
	}

}

func parseTCPPacket(packet []byte) {
	srcPort := int(packet[0])<<8 | int(packet[1])
	dstPort := int(packet[2])<<8 | int(packet[3])

	fmt.Printf("TCP Packet - Source Port: %d, Destination Port: %d\n", srcPort, dstPort)
}

func parseUDPPacket(packet []byte) {
	srcPort := int(packet[0])<<8 | int(packet[1])
	dstPort := int(packet[2])<<8 | int(packet[3])

	fmt.Printf("UDP Packet - Source Port: %d, Destination Port: %d\n", srcPort, dstPort)
}
