package sipClassifier

/*
 * FILE_NAME:
 		sipClassifier.go
 * MODULE:
 		Sip Classifier
 * DESCRIPTION:
 		This file contains the SIP Classifier Module for VoIP-Traffic-Analyzer.
		sipClassifier Package contains functions to Setup Hyperscan, Compile Patterns, Classify packets as SIP/SDP & non SIP/SDP.
 * Expected Input:
		Classified UDP/TCP flow.
 * Expected Output:
		Classified SIP/SDP flow & non SIP flow.
*/

import (
	"fmt"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

/*
 *	FUNCTION_NAME :
 		Classify
 *	ARGS :
 		pkt (*packet.Packet) 		: 	Packet pointer
 		context (flow.userContext)	:	an interface from the output of copy()
 *	RETURN TYPE :
 		bool						: 	true for Non-SIP | false for SIP
 * 	DESCRIPTION :
 		This Functions Extracts Packet data from received packet and forwards the extrated data to
 	   "classifysipsdp" fuction which Performs pattern matching on packet data ..
*/
func Classify(pkt *packet.Packet, context flow.UserContext) bool {

	hs2 := context.(*HS)
	pktBytes := pkt.GetRawPacketBytes()
	return classifysipsdp(pktBytes, hs2)
}

/*
 *	FUNCTION_NAME :
 		classifysipsdp
 *	ARGS :
 		pktData	([]byte) 	:	Packet Bytes
 		hsctx	(*HS)	 	:	A pointer of struct HS(context).
 *	RETURN TYPE :
 		bool				:	True for Non-SIP | False for SIP
 * 	DESCRIPTION :
 		This function scans the received packetData using Hyperscan against for patterns in HS compiled pattern Database which is part of
 		received *HS argument
*/
func classifysipsdp(pktData []byte, hsctx *HS) bool {
	OnMatchCtx := new(bool)
	*OnMatchCtx = false
	hsctx.Bdb.Scan(pktData, hsctx.Scratchspace, onMatch, OnMatchCtx)
	return !(*OnMatchCtx)
}

/*
 *	FUNCTION_NAME :
 		onMatch
 *	ARGS :
 		id (uint) 			:	ID of the Matched pattern in unparsed patterns slice.
 		from (uint64)		:	Byte # of packetdata(packetdata as in Scan() function of Classify()) from where match started
  		to (uint64)			:	Byte # of packetdata(packetdata as in Scan() function of Classify()) where match ended
 		flags (uint)		:	Not used but required in definition as per typedef
 		context (interface) :	Can be anything passed to this function for a match...e.g it can be whole packet if we want to extract mathing packets
 *	RETURN TYPE :
 		bool				:	True for Non-SIP | False for SIP
 * 	DESCRIPTION :
 		This function scans the received packetData using Hyperscan against for patterns in HS compiled pattern Database which is part of
 		received *HS argument
*/
func onMatch(id uint, from uint64, to uint64, flags uint, context interface{}) error {
	isMatch := context.(*bool)
	err := fmt.Errorf("Error : cease matching") //To Cease Scanning on a packet when any of Pattern match is found---we need to return non-nil error value
	// Report outside that match was found
	*isMatch = true
	return err
}
