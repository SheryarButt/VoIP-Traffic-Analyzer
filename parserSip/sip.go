package parserSip

/*
 * FILE_NAME:
 		sip.go
 * MODULE:
 		Parser SIP
 * DESCRIPTION:
 		This file contains the Parser SIP Module for VoIP-Traffic-Analyzer.
		The module is responsible for parsing of SIP packet in to a useable structure.
 * Expected Input:
		Raw bytes of SIP traffic.
 * Expected Output:
		SIP message structure.
*/

import (
	"bytes"
	"log"
	"strings"
)

//GLOBAL VARIABLES
var (
	KEEP_SRC        = true
	SEGREGATOR_FLAG = false
)

type SipMsg struct {
	Req    sipReq
	From   sipFrom
	To     sipTo
	CallId sipVal
	CellId sipVal

	Sdp SdpMsg
}

type SdpMsg struct {
	MediaDesc sdpMediaDesc
	ConnData  sdpConnData
}

type sipVal struct {
	Value []byte // Sip Value
	Src   []byte // Full source if needed
}

/*
 *	FUNCTION_NAME :
 		Parse
 *	ARGS :
 		v ([]byte)	: Packet Data in raw bytes.
 *	RETURN TYPE :
 		SipMsg		: User-defined Type (struct)
 * 	DESCRIPTION :
 		Main parsing routine, passes by value.
*/
func Parse(v []byte) (output SipMsg) {

	lines := bytes.Split(v, []byte("\r\n"))
	foundCellId := false
	for i, line := range lines {
		if i > 0 && output.Req.Method == nil && output.Req.StatusCode == nil {
			return
		}
		line = bytes.TrimSpace(line)
		if i == 0 {
			// For the first line parse the request
			parseSipReq(line, &output.Req)
		} else {
			// For subsequent lines split in sep (: for sip, = for sdp)
			spos, stype := indexSep(line)
			if !foundCellId {
				if spos > 0 && stype == ':' {
					// SIP: Break up into header and value
					lhdr := strings.ToLower(string(line[0:spos]))
					lval := bytes.TrimSpace(line[spos+1:])

					// Switch on the line header
					switch {
					case lhdr == "f" || lhdr == "from":
						parseSipFrom(lval, &output.From)
					case lhdr == "t" || lhdr == "to":
						parseSipTo(lval, &output.To)
					case lhdr == "i" || lhdr == "call-id":
						output.CallId.Value = lval
					case lhdr == "p-access-network-info":
						output.CellId.Src = lval
						lvalSplit := bytes.Split(lval, []byte(";"))
						for _, split := range lvalSplit {
							if bytes.HasPrefix(split, []byte("utran-cell-id-3gpp")) {
								if len(split) > 18 {
									id := split[19:]
									if len(id) > 5 && len(id) > 9 {
										output.CellId.Value = split[19:]
										foundCellId = true
									}
								}
							}
						}
					} // End of Switch
				}
			}
			if SEGREGATOR_FLAG {
				continue
			}
			if spos == 1 && stype == '=' {
				// SDP: Break up into header and value
				lhdr := strings.ToLower(string(line[0]))
				lval := bytes.TrimSpace(line[2:])
				// Switch on the line header
				switch {
				case lhdr == "m":
					parseSdpMediaDesc(lval, &output.Sdp.MediaDesc)
				case lhdr == "c":
					parseSdpConnectionData(lval, &output.Sdp.ConnData)

				} // End of Switch

			}
		}
	}

	return
}

/*
 *	FUNCTION_NAME :
 		indexSep
 *	ARGS :
 		s ([]byte)	: Packet Data in raw bytes.
 *	RETURN TYPE :
 		int			: Position of delimiter in byte array
		byte		: return delimiter type (':' or '=')
 * 	DESCRIPTION :
 		Finds the first valid Seperate or notes its type.
*/
func indexSep(s []byte) (index int, delim byte) {

	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i, ':'
		}
		if s[i] == '=' {
			return i, '='
		}
	}
	return -1, ' '
}

/*
 *	FUNCTION_NAME :
 		getString
 *	ARGS :
 		s1 ([]byte)	: Data in raw bytes.
		from (int)	: Start index of byte array
		to (int)	: Ending index of byte array
 *	RETURN TYPE :
 		string		: containing string equivalent of input raw bytes
 * 	DESCRIPTION :
 		Get a string from a slice of bytes, checks the bounds to avoid any range errors.
*/
func getString(sl []byte, from, to int) string {
	// Remove negative values
	if from < 0 {
		from = 0
	}
	if to < 0 {
		to = 0
	}
	// Limit if over len
	if from > len(sl) || from > to {
		return ""
	}
	if to > len(sl) {
		return string(sl[from:])
	}
	return string(sl[from:to])
}

/*
 *	FUNCTION_NAME :
 		getBytes
 *	ARGS :
 		s1 ([]byte)	: Data in raw bytes.
		from (int)	: Start index of byte array
		to (int)	: Ending index of byte array
 *	RETURN TYPE :
	 	[]byte		: containing byte equivalent of input raw bytes
 * 	DESCRIPTION :
 		Get a slice from a slice of bytes, checks the bounds to avoid any range errors.
*/
func getBytes(sl []byte, from, to int) []byte {
	// Remove negative values
	if from < 0 {
		from = 0
	}
	if to < 0 {
		to = 0
	}
	// Limit if over len
	if from > len(sl) || from > to {
		return nil
	}
	if to > len(sl) {
		return sl[from:]
	}
	return sl[from:to]
}

/*
 *	FUNCTION_NAME :
 		PrintSipStruct
 *	ARGS :
 		data (SipMsg)	: Pass by reference SipMsg structure.
 *	RETURN TYPE :
		None
 * 	DESCRIPTION :
 		Function to print all we know about the struct in a readable format as logs.
*/
func PrintSipStruct(data *SipMsg) {
	log.Println("-SIP --------------------------------")

	log.Println("  [REQ]")
	log.Println("    [UriType] =>", data.Req.UriType)
	log.Println("    [Method] =>", string(data.Req.Method))
	log.Println("    [StatusCode] =>", string(data.Req.StatusCode))
	log.Println("    [User] =>", string(data.Req.User))
	log.Println("    [Host] =>", string(data.Req.Host))
	log.Println("    [Port] =>", string(data.Req.Port))
	log.Println("    [UserType] =>", string(data.Req.UserType))
	log.Println("    [Src] =>", string(data.Req.Src))

	// FROM
	log.Println("  [FROM]")
	log.Println("    [UriType] =>", data.From.UriType)
	log.Println("    [Name] =>", string(data.From.Name))
	log.Println("    [User] =>", string(data.From.User))
	log.Println("    [Host] =>", string(data.From.Host))
	log.Println("    [Port] =>", string(data.From.Port))
	log.Println("    [Tag] =>", string(data.From.Tag))
	log.Println("    [Src] =>", string(data.From.Src))
	// TO
	log.Println("  [TO]")
	log.Println("    [UriType] =>", data.To.UriType)
	log.Println("    [Name] =>", string(data.To.Name))
	log.Println("    [User] =>", string(data.To.User))
	log.Println("    [Host] =>", string(data.To.Host))
	log.Println("    [Port] =>", string(data.To.Port))
	log.Println("    [Tag] =>", string(data.To.Tag))
	log.Println("    [UserType] =>", string(data.To.UserType))
	log.Println("    [Src] =>", string(data.To.Src))
	// CallId
	log.Println("  [Call-ID]")
	log.Println("    [Value] =>", string(data.CallId.Value))
	log.Println("    [Src] =>", string(data.CallId.Src))

	// CellId
	log.Println("  [Cell-ID]")
	log.Println("    [Value] =>", string(data.CellId.Value))
	log.Println("    [Src] =>", string(data.CellId.Src))

	log.Println("-SDP --------------------------------")
	// Media Desc
	log.Println("  [MediaDesc]")
	log.Println("    [MediaType] =>", string(data.Sdp.MediaDesc.MediaType))
	log.Println("    [Port] =>", string(data.Sdp.MediaDesc.Port))
	log.Println("    [Proto] =>", string(data.Sdp.MediaDesc.Proto))
	log.Println("    [Fmt] =>", string(data.Sdp.MediaDesc.Fmt))
	log.Println("    [Src] =>", string(data.Sdp.MediaDesc.Src))
	// Connection Data
	log.Println("  [ConnData]")
	log.Println("    [AddrType] =>", string(data.Sdp.ConnData.AddrType))
	log.Println("    [ConnAddr] =>", string(data.Sdp.ConnData.ConnAddr))
	log.Println("    [Src] =>", string(data.Sdp.ConnData.Src))
	log.Println("-------------------------------------")

}

//List of Constants
const FIELD_NULL = 0
const FIELD_BASE = 1
const FIELD_VALUE = 2
const FIELD_NAME = 3
const FIELD_NAMEQ = 4
const FIELD_USER = 5
const FIELD_HOST = 6
const FIELD_PORT = 7
const FIELD_TAG = 8
const FIELD_ID = 9
const FIELD_METHOD = 10
const FIELD_TRAN = 11
const FIELD_BRANCH = 12
const FIELD_RPORT = 13
const FIELD_MADDR = 14
const FIELD_TTL = 15
const FIELD_REC = 16
const FIELD_EXPIRES = 17
const FIELD_Q = 18
const FIELD_USERTYPE = 19
const FIELD_STATUS = 20
const FIELD_STATUSDESC = 21

const FIELD_ADDRTYPE = 40
const FIELD_CONNADDR = 41
const FIELD_MEDIA = 42
const FIELD_PROTO = 43
const FIELD_FMT = 44
const FIELD_CAT = 45

const FIELD_IGNORE = 255
