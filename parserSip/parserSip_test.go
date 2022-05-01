package parserSip

/*
 * FILE_NAME:
 		parserSip_test.go
 * MODULE:
 		Parser SIP
 * DESCRIPTION:
 		This file contains unit tests for parserSip module.
*/

import (
	"testing"
)

/*
 *	FUNCTION_NAME :
		TestParseTo
 *	ARGS :
 		testing.T	: Pointer to testing.T struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Unit tests for parserSip module "To" header.
*/
func TestParseTo(t *testing.T) {
	var to sipTo
	toHeader1 := []byte("<sip:0543220428@ims.etisalat.ae;user=phone>")
	toHeader2 := []byte("\"0567464589\" <sip:0567464589@ims.etisalat.ae>;tag=0ml52mg2-CC-1070-OFC-116")
	toHeader3 := []byte("")
	parseSipTo(toHeader1, &to)

	if string(to.User) != "0543220428" {
		t.Errorf("ParseTo failed, expected %v, got %v", "0543220428", string(to.User))
	}
	parseSipTo(toHeader2, &to)
	if string(to.User) != "0567464589" {
		t.Errorf("ParseTo failed, expected %v, got %v", "0567464589", string(to.User))
	}
	parseSipTo(toHeader3, &to)
	if string(to.User) != "" {
		t.Errorf("ParseTo failed, expected %v, got %v", "", string(to.User))
	}
}

/*
 *	FUNCTION_NAME :
		TestParseFrom
 *	ARGS :
 		testing.T	: Pointer to testing.T struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Unit tests for parserSip module "From" header.
*/
func TestParseFrom(t *testing.T) {
	var from sipFrom
	fromHeader1 := []byte("<sip:0543220428@ims.etisalat.ae;user=phone>")
	fromHeader2 := []byte("\"0567464589\" <sip:0567464589@ims.etisalat.ae>;tag=0ml52mg2-CC-1070-OFC-116")
	fromHeader3 := []byte("")
	parseSipFrom(fromHeader1, &from)

	if string(from.User) != "0543220428" {
		t.Errorf("ParseTo failed, expected %v, got %v", "0543220428", string(from.User))
	}
	parseSipFrom(fromHeader2, &from)
	if string(from.User) != "0567464589" {
		t.Errorf("ParseTo failed, expected %v, got %v", "0567464589", string(from.User))
	}

	parseSipFrom(fromHeader3, &from)
	if string(from.User) != "" {
		t.Errorf("ParseTo failed, expected %v, got %v", "", string(from.User))
	}
}

/*
 *	FUNCTION_NAME :
		TestParseMediaConnection
 *	ARGS :
 		testing.T	: Pointer to testing.T struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Unit tests for parserSip module SDP "c" field header.
*/
func TestParseMediaConnection(t *testing.T) {
	var sdp sdpConnData
	sdpheader1 := []byte("IN IP4 10.238.238.46")
	sdpheader2 := []byte("")
	parseSdpConnectionData(sdpheader1, &sdp)

	if string(sdp.ConnAddr) != "10.238.238.46" {
		t.Errorf("parseSdpConnectionData failed, expected %v, got %v", "10.238.238.46", string(sdp.ConnAddr))
	}

	parseSdpConnectionData(sdpheader2, &sdp)

	if string(sdp.ConnAddr) != "" {
		t.Errorf("parseSdpConnectionData failed, expected %v, got %v", "", string(sdp.ConnAddr))
	}
}

/*
 *	FUNCTION_NAME :
		TestParseMediaDesc
 *	ARGS :
 		testing.T	: Pointer to testing.T struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Unit tests for parserSip module SDP "m" field header.
*/
func TestParseMediaDesc(t *testing.T) {
	var sdp sdpMediaDesc
	sdpheader1 := []byte("audio 48008 RTP/AVP 8 18 101")
	sdpheader2 := []byte("")
	parseSdpMediaDesc(sdpheader1, &sdp)

	if string(sdp.Port) != "48008" {
		t.Errorf("parseSdpMediaDesc failed, expected %v, got %v", "48008", string(sdp.Port))
	}

	parseSdpMediaDesc(sdpheader2, &sdp)

	if string(sdp.Port) != "" {
		t.Errorf("parseSdpMediaDesc failed, expected %v, got %v", "", string(sdp.Port))
	}
}

/*
 *	FUNCTION_NAME :
		TestParse
 *	ARGS :
 		testing.T	: Pointer to testing.T struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Unit test for parserSip module main parsing routine.
*/
func TestParse(t *testing.T) {
	raw := []byte("INVITE sip:+971543220428@ims.etisalat.ae;user=phone SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 10.238.235.250:5082;branch=z9hG4bK1602159045-231147484\r\n" +
		"Route: <sip:3Zqkv7%25bqGiaaaaaesxUI6aUWY55KhndapjxCoyicWaasip%3A%2B97143402069%40ims.etisalat.aeOQ7scGeaebC@10.238.235.245:5060;lr>\r\n" +
		"Max-Forwards: 67\r\n" +
		"Allow: REGISTER,REFER,NOTIFY,SUBSCRIBE,PRACK,PUBLISH,INFO,UPDATE,INVITE,ACK,OPTIONS,CANCEL,BYE\r\n" +
		"From: sip:+97142323337@ims.etisalat.ae;tag=p65552t1566904455m976145c672395355s1_1602159063-1917554917\r\n" +
		"To: <sip:0543220428@ims.etisalat.ae;user=phone>\r\n" +
		"Call-ID: p65552t1566904455m976145c672395355s2\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Min-SE: 900\r\n" +
		"Session-Expires: 1800\r\n" +
		"Supported: timer,replaces\r\n" +
		"Contact: sip:p65552t1566904455m976145c672395355s1@10.238.235.250:5082;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"\r\n" +
		"Privacy: none\r\n" +
		"P-Visited-Network-ID: ims.etisalat.ae\r\n" +
		"P-Served-User: sip:+97143402069@ims.etisalat.ae;sescase=orig;regstate=reg\r\n" +
		"Session-ID:589f328469aa6aabb25618691a776b74" +
		"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"\r\n" +
		"P-Early-Media: supported\r\n" +
		"Accept: application/sdp\r\n" +
		"P-Charging-Function-Addresses: ccf=\"aaa://mmec.ims.etisalat.ae:3868;transport=tcp\"\r\n" +
		"P-Charging-Vector: icid-value=sbg03-sgc4.ims.etisalat.ae-1566-904455-981125;icid-generated-at=sbg03-sgc4.ims.etisalat.ae;orig-ioi=ims.etisalat.ae\r\n" +
		"P-Asserted-Identity: <sip:+97142323337@ims.etisalat.ae>\r\n" +
		"P-Access-Network-Info: ADSL2+;sbc-domain=ims.etisalat.ae;ue-ip=10.130.61.63;network-provided;e2down.ims.etisalat.ae\r\n" +
		"Allow-Events: hold,talk\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 260\r\n" +
		"v=0\r\n" +
		"o=- 78109303 1602158753 IN IP4 10.238.235.250\r\n" +
		"s=Session SDP\r\n" +
		"c=IN IP4 10.238.238.46\r\n" +
		"t=0 0\r\n" +
		"m=audio 48008 RTP/AVP 8 18 101\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:18 G729/8000\r\n" +
		"a=fmtp:18 annexb=no\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-15\r\n" +
		"a=ptime:20\r\n")

	sip := Parse(raw)

	if string(sip.To.User) != "0543220428" {
		t.Errorf("Parse SIP failed, expected %v, got %v", "0543220428", string(sip.To.User))
	} else if string(sip.From.User) != "+97142323337" {
		t.Errorf("Parse SIP failed, expected %v, got %v", "+97142323337", string(sip.From.User))
	} else if string(sip.CallId.Value) != "p65552t1566904455m976145c672395355s2" {
		t.Errorf("Parse SIP failed, expected %v, got %v", "p65552t1566904455m976145c672395355s2", string(sip.CallId.Value))
	} else if string(sip.CellId.Value) != "" {
		t.Errorf("Parse SIP failed, expected %v, got %v", nil, string(sip.CellId.Value))
	} else if string(sip.Sdp.ConnData.ConnAddr) != "10.238.238.46" {
		t.Errorf("Parse SIP failed, expected %v, got %v", "10.238.238.46", string(sip.Sdp.ConnData.ConnAddr))
	} else if string(sip.Sdp.MediaDesc.Port) != "48008" {
		t.Errorf("Parse SIP failed, expected %v, got %v", "48008", string(sip.Sdp.MediaDesc.Port))
	}
}

/*
 *	FUNCTION_NAME :
		BenchmarkParser
 *	ARGS :
 		testing.B	: Pointer to testing.B struct.
 *	RETURN TYPE :
 		None
 * 	DESCRIPTION :
 		Benchmark for parserSip module main parsing routine.
*/

func BenchmarkParser(b *testing.B) {
	raw := []byte("INVITE sip:+971543220428@ims.etisalat.ae;user=phone SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 10.238.235.250:5082;branch=z9hG4bK1602159045-231147484\r\n" +
		"Route: <sip:3Zqkv725bqGiaaaaaesxUI6aUWY55KhndapjxCoyicWaasip%3A%2B97143402069%40ims.etisalat.aeOQ7scGeaebC@10.238.235.245:5060;lr>\r\n" +
		"Max-Forwards: 67\r\n" +
		"Allow: REGISTER,REFER,NOTIFY,SUBSCRIBE,PRACK,PUBLISH,INFO,UPDATE,INVITE,ACK,OPTIONS,CANCEL,BYE\r\n" +
		"From: sip:+97142323337@ims.etisalat.ae;tag=p65552t1566904455m976145c672395355s1_1602159063-1917554917\r\n" +
		"To: <sip:0543220428@ims.etisalat.ae;user=phone>\r\n" +
		"Call-ID: p65552t1566904455m976145c672395355s2\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Min-SE: 900\r\n" +
		"Session-Expires: 1800\r\n" +
		"Supported: timer,replaces\r\n" +
		"Contact: sip:p65552t1566904455m976145c672395355s1@10.238.235.250:5082;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"\r\n" +
		"Privacy: none\r\n" +
		"P-Visited-Network-ID: ims.etisalat.ae\r\n" +
		"P-Served-User: sip:+97143402069@ims.etisalat.ae;sescase=orig;regstate=reg\r\n" +
		"Session-ID:589f328469aa6aabb25618691a776b74" +
		"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"\r\n" +
		"P-Early-Media: supported\r\n" +
		"Accept: application/sdp\r\n" +
		"P-Charging-Function-Addresses: ccf=\"aaa://mmec.ims.etisalat.ae:3868;transport=tcp\"\r\n" +
		"P-Charging-Vector: icid-value=sbg03-sgc4.ims.etisalat.ae-1566-904455-981125;icid-generated-at=sbg03-sgc4.ims.etisalat.ae;orig-ioi=ims.etisalat.ae\r\n" +
		"P-Asserted-Identity: <sip:+97142323337@ims.etisalat.ae>\r\n" +
		"P-Access-Network-Info: ADSL2+;sbc-domain=ims.etisalat.ae;ue-ip=10.130.61.63;network-provided;e2down.ims.etisalat.ae\r\n" +
		"Allow-Events: hold,talk\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 260\r\n" +
		"v=0\r\n" +
		"o=- 78109303 1602158753 IN IP4 10.238.235.250\r\n" +
		"s=Session SDP\r\n" +
		"c=IN IP4 10.238.238.46\r\n" +
		"t=0 0\r\n" +
		"m=audio 48008 RTP/AVP 8 18 101\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:18 G729/8000\r\n" +
		"a=fmtp:18 annexb=no\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-15\r\n" +
		"a=ptime:20\r\n")

	for i := 0; i < b.N; i++ {
		Parse(raw)
	}
	b.ReportAllocs()
}
