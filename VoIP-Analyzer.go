package main

import (
	"VoIP-Analyzer/common"
	"VoIP-Analyzer/protocolIdentifier"

	"github.com/intel-go/nff-go/flow"
)

// Main function for constructing packet processing graph.
func main() {

	common.SplashScreen()

	config := flow.Config{
		CPUList:     "",
		MemoryJumbo: true,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	flowInput, err := flow.SetReceiver(0)
	flow.CheckFatal(err)

	flowPBF, _ := flow.SetSplitter(flowInput, protocolIdentifier.Identify, 3, nil)

	flow.CheckFatal(flow.SetSender(flowPBF[protocolIdentifier.NON_TCP], 0))
	flow.CheckFatal(flow.SetSender(flowPBF[protocolIdentifier.TCP], 0))
	flow.CheckFatal(flow.SetSender(flowPBF[protocolIdentifier.RTP], 0))

	flow.SystemStart()

}
