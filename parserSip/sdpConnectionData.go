package parserSip

/*
 * FILE_NAME:
 		sdpConnectionData.go
 * MODULE:
 		Parser SIP
 * DESCRIPTION:
 		This file contains the Parser SIP Module for VoIP-Traffic-Analyzer.
		Package containing functions responible for parsing of SDP Connection Infromation from packets.
*/

/*
RFC4566 - https://tools.ietf.org/html/rfc4566#section-5.7

5.7.  Connection Data ("c=")

  c=<nettype> <addrtype> <connection-address>

  c=IN IP4 88.215.55.98
  c=IN IP6 FF15::101/3

*/

type sdpConnData struct {
	//NetType   []byte // Network Type
	AddrType []byte // Address Type
	ConnAddr []byte // Connection Address
	Src      []byte // Full source if needed
}

/*
 * FUNCTION_NAME: parseSdpConnectionData
 * ARGS:
 *	@_arg1 ([]byte)	: Packet Data in raw bytes.
 *	@_arg2 (sdpConnData)	: Pass by reference sdpConnData struct.
 * DESCRIPTION: Parsing routine for SDP connection data parsing.
 */
func parseSdpConnectionData(v []byte, out *sdpConnData) {

	pos := 0
	state := FIELD_BASE

	// Init the output area
	//out.NetType = nil
	out.AddrType = nil
	out.ConnAddr = nil
	out.Src = nil

	// Keep the source line if needed
	if KEEP_SRC {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		// FSM
		switch state {
		case FIELD_BASE:
			if v[pos] == ' ' {
				state = FIELD_ADDRTYPE
				pos++
				continue
			}
		case FIELD_ADDRTYPE:
			if v[pos] == ' ' {
				state = FIELD_CONNADDR
				pos++
				continue
			}
			out.AddrType = append(out.AddrType, v[pos])

		case FIELD_CONNADDR:
			if v[pos] == ' ' {
				state = FIELD_BASE
				pos++
				// continue
				return
			}
			out.ConnAddr = append(out.ConnAddr, v[pos])
		}
		pos++
	}
}
