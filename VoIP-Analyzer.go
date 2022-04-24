package main

/*
 * FILE_NAME:
 		VoIP-Analyzer.go
 * MODULE:
 		Main
 * DESCRIPTION:
 		This file contains the Main Module for VoIP-Traffic-Analyzer.
 * Expected Input:
		General IP Reassembled IMS traffic.
 * Expected Output:
		General IP Reassembled IMS traffic after analysis.
*/

import (
	"VoIP-Analyzer/common"
	"VoIP-Analyzer/protocolIdentifier"
	"VoIP-Analyzer/sipClassifier"

	"github.com/intel-go/nff-go/flow"
)

func init() {
	sipClassifier.PatternSetup()
}

/*
 *	FUNCTION_NAME :
 		main
 *	FUNCTION TYPE :
 		Main Function
 *	ARGS :
 		None
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
		Main function for constructing packet processing graph.
*/

func main() {

	common.SplashScreen()
	var Hs_Obj = new(sipClassifier.HS)

	config := flow.Config{
		CPUList:     "",
		MemoryJumbo: true,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	flowInput, err := flow.SetReceiver(0)
	flow.CheckFatal(err)

	flowPI, _ := flow.SetSplitter(flowInput, protocolIdentifier.Identify, 3, nil)
	flow.CheckFatal(flow.SetSender(flowPI[protocolIdentifier.RTP], 0))

	flowSIPTcp, _ := flow.SetSeparator(flowPI[protocolIdentifier.TCP], sipClassifier.Classify, Hs_Obj)
	flow.CheckFatal(flow.SetSender(flowPI[protocolIdentifier.TCP], 0))

	flowSIPUdp, _ := flow.SetSeparator(flowPI[protocolIdentifier.NON_TCP], sipClassifier.Classify, Hs_Obj)
	flow.CheckFatal(flow.SetSender(flowPI[protocolIdentifier.NON_TCP], 0))

	flow.CheckFatal(flow.SetSender(flowSIPTcp, 0))
	flow.CheckFatal(flow.SetSender(flowSIPUdp, 0))

	flow.SystemStart()

}
