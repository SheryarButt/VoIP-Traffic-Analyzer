package sipClassifier

/*
 * FILE_NAME:
 		hyerScan.go
 * MODULE:
 		Sip Classifier
 * DESCRIPTION:
 		This file contains Hyperscan setup for Module Sip Classifier.
 * Expected Input:
		None
 * Expected Output:
		None
*/

import (
	"log"

	"github.com/flier/gohs/hyperscan"
	"github.com/intel-go/nff-go/flow"
)

// HS is a struct containing Hyperscan objects
type HS struct {
	Bdb          hyperscan.BlockDatabase
	Scratchspace *hyperscan.Scratch
}

// Global Variables
var (
	ERR             error
	PARSED_PATTERNS []*hyperscan.Pattern
)

/*
 *	FUNCTION_NAME :
 		Copy
 *	ARGS :
 		None			:	Takes no arguments & is called by a context , when system switch cores
 *	RECEIVER :
	 	hs (struct HS)	:	An object of struct HS
 *	RETURN TYPE :
 		interface		:	Returns an interface type containing an newly setup object of struct HS
 * 	DESCRIPTION :
 		Setups Compile patterns Database & Scratch Space to be used by Hyperscan.
*/
func (Hs_Obj HS) Copy() interface{} {
	PatternSetup()
	hs1 := new(HS)
	hs1.Bdb, ERR = hyperscan.NewBlockDatabase(PARSED_PATTERNS...)
	if ERR != nil {
		log.Fatal("Error comiling Hyperscan patterns: ", ERR)
	}
	hs1.Scratchspace, ERR = hyperscan.NewScratch(hs1.Bdb)
	flow.CheckFatal(ERR)
	return hs1
}

func (Hs_Obj HS) Delete() {
}

/*
 *	FUNCTION_NAME :
 		PatternSetup
 *	ARGS :
 		None
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Defines Patterns to match SIP/SDP Packets & calls parsepatterns() for processing the provided patterns.
*/
func PatternSetup() {
	unparsedPatterns := []string{"Accept/i", "/Accept-Contact/i", "/Accept-Encoding/i", "/Accept-Language/i", "/Accept-Resource-Priority/i", "/Additional-Identity/i", "/Alert-Info/i",
		"/AlertMsg-Error/i", "/Allow/i", "/Allow-Events/i", "/Answer-Mode/i", "/Attestation-Info/i", "/Authentication-Info/i", "/Authorization/i", "/Call-ID/i", "/Call-Info/i",
		"/Cellular-Network-Info/i", "/Contact/i", "/Content-Disposition/i", "/Content-Encoding/i", "/Content-ID/i", "/Content-Language/i", "/Content/i", "-Length/i", "/Content-Type/i",
		"/CSeq/i", "/Date/i", "/Encryption/i", "/Error-Info/i", "/Event/i", "/Expires/i", "/Feature-Caps/i", "/Flow-Timer/i", "/From/i", "/Geolocation/i", "/Geolocation-Error/i",
		"/Geolocation-Routing/i", "/Hide/i", "/History-Info/i", "/Identity/i", "/Identity-Info/i", "/Info-Package/i", "/In-Reply-To/i", "/Join/i", "/Max-Breadth/i", "/Max-Forwards/i",
		"/MIME-Version/i", "/Min-Expires/i", "/Min-SE/i", "/Organization/i", "/Origination-Id/i", "/P-Access-Network-Info/i", "/P-Answer-State/i", "/P-Asserted-Identity/i",
		"/P-Asserted-Service/i", "/P-Associated-URI/i", "/P-Called-Party-ID/i", "/P-Charge-Info/i", "/P-Charging-Function-Addresses/i", "/P-Charging-Vector/i", "/P-DCS-Trace-Party-ID/i",
		"/P-DCS-OSPS/i", "/P-DCS-Billing-Info/i", "/P-DCS-LAES/i", "/P-DCS-Redirect/i", "/P-Early-Media/i", "/P-Media-Authorization/i", "/P-Preferred-Identity/i", "/P-Preferred-Service/i",
		"/P-Private-Network-Indication/i", "/P-Profile-Key/i", "/P-Refused-URI-List/i", "/P-Served-User/i", "/P-User-Database/i", "/P-Visited-Network-ID/i", "/Path/i", "/Permission-Missing/i",
		"/Policy-Contact/i", "/Policy-ID/i", "/Priority/i", "/Priority-Share/i", "/Priv-Answer-Mode/i", "/Privacy/i", "/Proxy-Authenticate/i", "/Proxy-Authorization/i", "/Proxy-Require/i",
		"/RAck/i", "/Reason/i", "/Reason-Phrase/i", "/Record-Route/i", "/Recv-Info/i", "/Refer-Events-At/i", "/Refer-Sub/i", "/Refer-To/i", "/Referred-By/i", "/Reject-Contact/i",
		"/Relayed-Charge/i", "/Replaces/i", "/Reply-To/i", "/Request-Disposition/i", "/Require/i", "/Resource-Priority/i", "/Resource-Share/i", "/Response-Key/i", "/Response-Source/i",
		"/Restoration-Info/i", "/Retry-After/i", "/Route/i", "/RSeq/i", "/Security-Client/i", "/Security-Server/i", "/Security-Verify/i", "/Server/i", "/Service-Interact-Info/i",
		"/Service-Route/i", "/Session-Expires/i", "/Session-ID/i", "/SIP-ETag/i", "/SIP-If-Match/i", "/Subject/i", "/Subscription-State/i", "/Supported/i", "/Suppress-If-Match/i",
		"/Target-Dialog/i", "/Timestamp/i", "/To/i", "/Trigger/i", "-Consent/i", "/Unsupported/i", "/User-Agent/i", "/User-to-User/i", "/Via/i", "/Warning/i", "/WWW-Authenticate/i",
		"/sip.2.0/i", "/sip[:.]/i", "5060", "5160", "/application.sdp/i", "/invite sip:/i", "/invite/i", "/register sip:/i", "/ack sip:/i", "/bye sip:/i", "/cancel sip:/i", "/options sip:/i",
		"/PUBLISH sip:/i", "/INFO sip:/i", "/PRACK sip:/i", "/prack/i", "/SUBSCRIBE sip:/", "/NOTIFY sip:/i", "/UPDATE sip:/i", "/MESSAGE sip:/i", "/refer/i", "/REFER sip:/",
		"/a=/", "/b=/", "/c=/", "/v=/", "/o=/", "/s=/", "/i=/", "/e=/", "/u=/", "/p=/", "/z=/", "/k=/", "/m=/"}
	PARSED_PATTERNS = PatternParser(unparsedPatterns)
}

/*
 *	FUNCTION_NAME :
 		PatternParser
 *	ARGS :
 		unparsed ([]string) :	a slice of string patterns to be compiled and later used by Hyperscan for matching
 *	RETURN TYPE :
 		parsed ([]*hyperscan.Pattern) : A pointer to Slice of Patterns in Hyperscan compatible fashion
 * 	DESCRIPTION :
 		Compiles patterns in a suitable way to be used by Hyperscan to setup pattern Database
*/
func PatternParser(unParsed []string) (parsed []*hyperscan.Pattern) {
	for k, v := range unParsed {
		p, err := hyperscan.ParsePattern(v)
		if err != nil {
			log.Fatal("Error parsing Hyperscan patterns : ", err)
		}
		p.Id = k
		parsed = append(parsed, p)
	}
	return parsed
}
