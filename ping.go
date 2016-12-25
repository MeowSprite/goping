package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

func main() {
	ping()
}

/*ICMPHeader is the packet form of ICMP Packet*/
type ICMPHeader struct {
	Type       uint8
	Code       uint8
	CheckSum   uint16
	Identifier uint16
	SeqNum     uint16
	Data       []byte
}

func (packet *ICMPHeader) getTimeStamp() uint64 {
	length := len(packet.Data)
	if packet.Data == nil || length == 0 {
		return 0
	}
	if maxlength := 8; length < maxlength {
		data := make([]byte, maxlength)
		for length >= 0 {
			data[maxlength-1] = packet.Data[length-1]
			maxlength--
			length--
		}
	}
	return binary.BigEndian.Uint64(packet.Data)
}

func (packet *ICMPHeader) checkIdentifier() bool {
	return packet.Identifier == uint16(os.Getpid())
}

func (packet *ICMPHeader) checkCheckSum() bool {
	packetSum := packet.genCheckSum()
	return packetSum == packet.CheckSum
}

func (packet *ICMPHeader) genCheckSum() uint16 {
	var sum, i uint32
	sum = uint32(packet.Type)<<8 + uint32(packet.Code)
	sum += uint32(packet.Identifier) + uint32(packet.SeqNum)
	dataLen := len(packet.Data)
	for dataLen > 1 {
		sum += uint32(packet.Data[i])<<8 + uint32(packet.Data[i+1])
		dataLen -= 2
		i += 2
	}
	if dataLen == 1 {
		sum += uint32(packet.Data[i]) << 8
	}

	sum += sum >> 16
	return uint16(^sum)
}

var reqAddr string
var runing bool

var receiveNumAtomic int32

func ping() {
	//args input
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("warning: no address input， to use : 127.0.0.1")
		reqAddr = "127.0.0.1"
	} else {
		reqAddr = args[0]
		if len(args) > 1 {
			fmt.Println("warning: the first address used only : " + args[1])
		}
	}

	runing = true

	//deal with Interrupt Signal <ctrl+c>
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	//create IPConn to send icmp packet
	conn, err := net.Dial("ip4:icmp", reqAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	//start listen goroutine
	go listenReply()

	//get start time
	startTime := time.Now().UnixNano()
	//packet sequence number
	var seq int32
	//start send packet
	for runing {
		reqPacket := newPack(uint16(seq))
		//send icmp packet
		if _, err := conn.Write(reqPacket); err != nil {
			log.Fatal(err)
			return
		}
		select {
		//stop program if Interrupt Signal arrived
		case <-sigChan:
			runing = false
			break
		//send new icmp request per second
		case <-time.After(time.Second):
			seq++
		}
	}
	//get end time
	endTime := time.Now().UnixNano()
	//get received packet number
	receivedNum := atomic.LoadInt32(&receiveNumAtomic)
	fmt.Printf("\n--- %v ping statistics ---\n", reqAddr)
	fmt.Printf("%v packets transmitted, %v received, %v%% packet loss, time %vms\n",
		seq+1,
		receivedNum,
		float32(seq-receivedNum+1)/float32(seq),
		(endTime-startTime)/1000000)
}

func listenReply() {
	//create listener IPConn
	lAddr, err := net.ResolveIPAddr("ip4", "")
	if err != nil {
		log.Fatal(err)
	}
	responConn, err := net.ListenIP("ip4:icmp", lAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer responConn.Close()

	for runing {
		resData := make([]byte, 1024)
		//use readfrom instead of read
		len, _, err := responConn.ReadFrom(resData)
		if err != nil {
			log.Fatal(err)
			return
		}
		resData = resData[:len]

		//deal with the packet
		go func(resData []byte) {
			resTimeStamp := uint64(time.Now().UnixNano())
			resPacket := getDataPacket(resData)
			if resPacket.checkCheckSum() {
				atomic.AddInt32(&receiveNumAtomic, 1)
				reqTimeStamp := resPacket.getTimeStamp()
				fmt.Printf("%v bytes from %v: icmp_seq=%v time %.3vms\n", len, reqAddr, 0, float64(resTimeStamp-reqTimeStamp)/1000000)
			} else {
				fmt.Println("unpack error")
			}
		}(resData)
	}
}

// create a new icmp packet data
func newPack(seqNum uint16) []byte {
	var packet = ICMPHeader{
		Type:       8,
		Code:       0,
		CheckSum:   0,
		Identifier: uint16(os.Getpid()),
		SeqNum:     seqNum,
		Data:       make([]byte, 8),
	}
	//set time stamp to Data
	timeStamp := uint64(time.Now().UnixNano())
	binary.BigEndian.PutUint64(packet.Data, timeStamp)
	//checkSum
	packet.CheckSum = packet.genCheckSum()
	return getPacketData(&packet)
}

//transform ICMPHeader Struct to []byte data
func getPacketData(packet *ICMPHeader) []byte {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, packet.Type)
	binary.Write(&buffer, binary.BigEndian, packet.Code)
	binary.Write(&buffer, binary.BigEndian, packet.CheckSum)
	binary.Write(&buffer, binary.BigEndian, packet.Identifier)
	binary.Write(&buffer, binary.BigEndian, packet.SeqNum)
	binary.Write(&buffer, binary.BigEndian, packet.Data)
	return buffer.Bytes()
}

//transform []byte data to ICMPHeader Struct
func getDataPacket(data []byte) *ICMPHeader {
	return &ICMPHeader{
		Type:       data[0],
		Code:       data[1],
		CheckSum:   uint16(data[2])<<8 + uint16(data[3]),
		Identifier: uint16(data[4])<<8 + uint16(data[5]),
		SeqNum:     uint16(data[6])<<8 + uint16(data[7]),
		Data:       data[8:],
	}
}
