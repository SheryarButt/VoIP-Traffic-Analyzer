package common

/*
 * FILE_NAME:
 		common.go
 * MODULE:
 		Common
 * DESCRIPTION:
 		This file contains the Common Module for VoIP-Traffic-Analyzer.
		This module consists of most commonly used functions, shared by multiple modules.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"github.com/intel-go/nff-go/packet"
)

//Constants for ESP classification
const EspNumber = 0x32
const FragmentNumber = 0x2c
const AuthLen = 12
const EspTailLen = AuthLen + 2
const EspHeadLen = 8
const FragmentHeadLen = 8

//Struct to parse ESP Tail
type EspTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [AuthLen]byte
}

//Struct to parse Fragment Header
type FragmentHeader struct {
	nextHeader uint8
}

/*
 *	FUNCTION_NAME :
 		CheckESPProtocol
 *	ARGS :
 		cur (*packet.Packet)	: Pointer to Current Packet.
 *	RETURN TYPE :
 		uint					: 17 for UDP | 06 for TCP
 * 	DESCRIPTION :
 		Identifies protcol in ESP tail and returns its Protocol ID.
*/
func CheckESPProtocol(currentPacket *packet.Packet) uint8 {
	length := currentPacket.GetPacketLen()
	currentESPTail := (*EspTail)(unsafe.Pointer(currentPacket.StartAtOffset(uintptr(length) - EspTailLen)))
	return currentESPTail.nextIP
}

/*
 *	FUNCTION_NAME :
 		CheckFragmentedProtocol
 *	ARGS :
 		cur (*packet.Packet)	: Pointer to Current Packet.
 		hdrLen (uint8)			: Start header length.
 *	RETURN TYPE :
 		uint					: 50 for ESP | 17 for UDP | 06 for TCP
 * 	DESCRIPTION :
 		Identifies protcol in IPv6 Fragment and returns its next Protocol ID.
*/
func CheckFragmentedProtocol(currentPacket *packet.Packet, hdrLen uint8) uint8 {
	fragmentHdr := (*FragmentHeader)(unsafe.Pointer(currentPacket.StartAtOffset(uintptr(hdrLen))))
	return fragmentHdr.nextHeader
}

/*
 *	FUNCTION_NAME :
 		SplashScreen
 *	ARGS :
 		None
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Just a simple splash screen to show the start of the program.
*/
func SplashScreen() {

	cmd := exec.Command("sh", "-c", "clear")
	cmd.Stdout = os.Stdout
	cmd.Run()

	fmt.Println(`
				 _    __ ____   ____ ____     ___     _   __ ___     __ __  __ _____    ______ ____ 
				| |  / // __ \ /  _// __ \   /   |   / | / //   |   / / \ \/ //__  /   / ____// __ \
				| | / // / / / / / / /_/ /  / /| |  /  |/ // /| |  / /   \  /   / /   / __/  / /_/ /
				| |/ // /_/ /_/ / / ____/  / ___ | / /|  // ___ | / /___ / /   / /__ / /___ / _, _/ 
				|___/ \____//___//_/      /_/  |_|/_/ |_//_/  |_|/_____//_/   /____//_____//_/ |_| 
				 `)
}
