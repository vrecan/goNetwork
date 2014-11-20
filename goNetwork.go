package main

import (
	"code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"runtime"
	"time"
)

func main() {
	threads := 3
	runtime.GOMAXPROCS(threads)

	if handle, err := pcap.OpenLive("bridge0", 65536, false, 1*time.Second); err != nil {
		panic(err)
	} else {

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true

		packets := make([][]gopacket.Packet, threads)
		fmt.Println("Start")
		channels := make([]chan []gopacket.Packet, threads)
		for k, c := range channels {
			c = make(chan []gopacket.Packet, 1000)
			channels[k] = c
			go packetHandler(c)
		}
		// channels := []chan gopacket.Packet
		packetsChan := packetSource.Packets()
		statsChan := time.NewTicker(time.Second * 1).C
		forceSend := time.NewTicker(time.Second * 5).C
		var prev pcap.Stats
		pkts := 0
		for {
			select {
			case p := <-packetsChan:
				{
					if pkts == 0 {

						for k, _ := range packets {
							packets[k] = make([]gopacket.Packet, 100)
						}
					}
					if net := p.NetworkLayer(); net != nil {
						// fmt.Println(int(net.NetworkFlow().Reverse().FastHash()) & 0x7)
						hash := int(net.NetworkFlow().FastHash() & 0x2)
						// fmt.Println(hash)
						// fmt.Println(hash)
						packets[hash] = append(packets[hash], p)
						pkts++
						if pkts >= 100 {
							for k, v := range packets {
								channels[k] <- v

							}
							pkts = 0
						}
					}
				}
			case <-statsChan:
				{
					stats, _ := handle.Stats()

					fmt.Println(stats)
					fmt.Println("pkt/s: ", stats.PacketsReceived-prev.PacketsReceived)
					prev = *stats
				}

			case <-forceSend:
				{
					if pkts > 0 {
						fmt.Println("Force sending pkts : ", pkts)
						for k, v := range packets {
							channels[k] <- v

						}
						pkts = 0
					}
				}

			}
		}
	}
}

func packetHandler(packets <-chan []gopacket.Packet) {
	fmt.Println("Starting packet handler")
	for {
		select {
		case pkts := <-packets:
			{
				for _, p := range pkts {
					if p == nil {

					} else {
						// v := p.Dump()

						for _, l := range p.Layers() {
							t := l.LayerType()
							_ = t

							// fmt.Printf("->%s", l.LayerType())

						}
						// fmt.Println("")
						// fmt.Println(p)
						_ = p
					}
				}
			}
		}
	}
	fmt.Println("Finished processing packets")
}

// channels := [8]chan gopacket.Packet
// for i := 0; i < 8; i++ {
//   channels[i] = make(chan gopacket.Packet)
//   go packetHandler(channels[i])
// }
// for packet := range getPackets() {
//   if net := packet.NetworkLayer(); net != nil {
//     channels[int(net.NetworkFlow().FastHash()) & 0x7] <- packet
//   }
// }
