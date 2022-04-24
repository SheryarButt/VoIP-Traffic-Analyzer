package protocolIdentifier

/*
 * FILE_NAME:
 		pi.go
 * MODULE:
 		Protocol Identifier
 * DESCRIPTION:
 		This file contains the Protocol Identifier Module for VoIP-Traffic-Analyzer.
		The module is responsible for segregation of traffic based on their protocol.
 * Expected Input:
		General IP Reassembled IMS traffic.
 * Expected Output:
		3 Separate flows containing TCP, Non TCP and RTP traffic.
*/

import (
	"VoIP-Analyzer/common"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	. "github.com/intel-go/nff-go/types"
)

const ( // Constants assigned to flows based on traffic.
	NON_TCP = iota
	TCP
	RTP
)

/*
 *	FUNCTION_NAME :
 		Identify
 *	FUNCTION TYPE :
 		NFF-GO SplitterFunction
 *	ARGS :
 		cur (*packet.Packet)		: Pointer to Current Packet
 		ctx (flow.UserContext)		: Nil
 *	RETURN TYPE :
 		uint						: 0 for Non-TCP | 1 for TCP | 2 for RTP
 * 	DESCRIPTION :
 		Segregates traffic into TCP, Non-TCP & RTP
*/

func Identify(cur *packet.Packet, ctx flow.UserContext) uint {

	var Proto uint8
	var HdrLen uint8 = EtherLen

	pktBytes := cur.GetRawPacketBytes()
	pktDataLen := len(pktBytes)

	if cur.GetVLAN() != nil { // Checking the presence of VLan tag to add to header length
		HdrLen += VLANLen
	}

	if cur.ParseDataCheckVLAN() == -1 { // Parse all known layers of the packet, Presence of ESP layer will cause the function to return '-1'
		pktIPv4, pktIPv6, _ := cur.ParseAllKnownL3CheckVLAN() // Parse layer 3 to identify if the packet is IPv4 or IPv6.
		if pktIPv4 != nil {
			HdrLen += IPv4MinLen
			Proto = pktIPv4.NextProtoID // Using NextProtoID in IPv4 header to identify if the next layer is ESP, ESP layer has a protocol ID of 50 or 0x32 in Hex
			if Proto == common.EspNumber {
				HdrLen += common.EspHeadLen
				Proto = common.CheckESPProtocol(cur) // Parsing protocol ID of the encapsulated layer present in the tail of ESP layer.
				pktDataLen = pktDataLen - common.EspTailLen
			}
		} else if pktIPv6 != nil {
			HdrLen += IPv6Len
			Proto = pktIPv6.Proto               // Using Proto in IPv6 header to identify if the next layer. Proto is 50 in case of ESP and 44 in case of fragmented IPv6 header.
			if Proto == common.FragmentNumber { // Inspecting if the IPv6 header is fragmented.
				Proto = common.CheckFragmentedProtocol(cur, HdrLen) // Parsing IPv6 fragment to retrieve protocol ID of next layer.
				HdrLen += common.FragmentHeadLen
			}
			if Proto == common.EspNumber {
				HdrLen += common.EspHeadLen
				Proto = common.CheckESPProtocol(cur) // Parsing protocol ID of the encapsulated layer present in the tail of ESP layer.
				pktDataLen = pktDataLen - common.EspTailLen
			}
		}
		if Proto == UDPNumber { // Checking if the packet has a UDP layer. Protocol ID for UDP is 17 or 0x11 in Hex.
			HdrLen += UDPLen
			if uintptr(HdrLen) > uintptr(pktDataLen) {
				return NON_TCP // If the packet is malformed, it's classified as a NON_TCP/UDP packet.
			}
			payload := pktBytes[HdrLen:pktDataLen] // Retrieving payload of packet by discarding headers till layer 4.
			payloadLength := len(payload)
			if payloadLength < 1 {
				return NON_TCP // If the packet does not contain any payload, it's classified as a NON_TCP/UDP packet.
			}
			/*
				Identifying if the packet can be classified as RTP or not based on the following key points
				- Layer 4 protocol is UDP and port number is greater than 1024 and even.
				- The version (first two bits of the header) field for RTP header is 2 and the payload type (bits 9-15) are in a range of 1-31 and 96-127. (These are the only constant bits in the header)
				- The UDP payload (the RTP header and payload) must be smaller than a maximum number (maximum size of (RTP header + payload)) and has to be greater than the minimum RTP header size i.e. 12 bytes.
			*/
			payloadType := (uint8)(payload[1] & 0x7F)
			if (payloadLength >= 12) && (((payload[0] & 0xFF) == 0x80) || ((payload[0] & 0xFF) == 0xA0)) && ((payloadType < 72) || (payloadType > 76)) && ((payloadType <= 34) || ((payloadType >= 96) && (payloadType <= 127))) {
				return RTP // Classify packet as RTP packet.
			}
			return NON_TCP
		}
	} else { // Packet does not contain any ESP or unknown layers. Packet can be parsed as a normal packet.
		IP4Hdr, IP6Hdr, _ := cur.ParseAllKnownL3CheckVLAN() // Parse layer 3 to identify if the packet is IPv4 or IPv6.
		if IP4Hdr != nil {                                  // In case the packet is of IPv4 type, the NextProtoID attribute is used to identify if the packet is UDP or TCP
			Proto = IP4Hdr.NextProtoID
		} else if IP6Hdr != nil { // In case the packet is of IPv6 type, the NextProtoID attribute is used to identify if the packet is UDP, TCP or Fragmented
			Proto = IP6Hdr.Proto
			if Proto == common.FragmentNumber { // Inspecting if the IPv6 header is fragmented.
				Proto = common.CheckFragmentedProtocol(cur, HdrLen) // Parsing IPv6 fragment to retrieve protocol ID of next layer.
			}
		}
		if Proto == UDPNumber { // Checking if the packet has a UDP layer. Protocol ID for UDP is 17 or 0x11 in Hex.

			/*
				If the packet is indeed a UDP packet, it is further inspected if it can be classified as an RTP packet or not.
				As RTP or Real-Time Transport Protocol uses UDP as it's transport protocol.
			*/

			pktStartAddr := cur.StartAtOffset(0)
			hdrsLen := uintptr(cur.Data) - uintptr(pktStartAddr)
			if hdrsLen > uintptr(pktDataLen) {
				return NON_TCP // If the packet is malformed, it's classified as a NON_TCP/UDP packet.
			}
			payload := pktBytes[hdrsLen:] // Retrieving payload of packet by discarding headers till layer 4.
			payloadLength := len(payload)
			if payloadLength < 1 {
				return NON_TCP // If the packet does not contain any payload, it's classified as a NON_TCP/UDP packet.
			}

			/*
				Identifying if the packet can be classified as RTP or not based on the following key points
				- Layer 4 protocol is UDP and port number is greater than 1024 and even.
				- The version (first two bits of the header) field for RTP header is 2 and the payload type (bits 9-15) are in a range of 1-31 and 96-127. (These are the only constant bits in the header)
				- The UDP payload (the RTP header and payload) must be smaller than a maximum number (maximum size of (RTP header + payload)) and has to be greater than the minimum RTP header size i.e. 12 bytes.
			*/

			payloadType := (uint8)(payload[1] & 0x7F)
			if (payloadLength >= 12) && (((payload[0] & 0xFF) == 0x80) || ((payload[0] & 0xFF) == 0xA0)) && ((payloadType < 72) || (payloadType > 76)) && ((payloadType <= 34) || ((payloadType >= 96) && (payloadType <= 127))) {
				return RTP // Classify packet as RTP packet.
			}
			return NON_TCP // If the packet is not classified as an RTP packet, it's classified as a NON_TCP/UDP packet.
		}
	}
	if Proto == TCPNumber { // Checking if the packet has a TCP layer. Protocol ID for TCP is 6 or 0x06 in Hex.
		return TCP // Classify packet as TCP packet.
	}
	return NON_TCP // If all conditions fail, the packet is forwarded to Non-TCP flow as a failsafe.
}
