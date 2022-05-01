# VoIP-Traffic-Analyzer SIP Parser Module Description
Sip Parser module uses a modified version of [SIP Rocket](https://github.com/marv2097/siprocket) with more focus on performace and ability to parse IPv6 packets, it takes SIP packet data as raw bytes. The packets should be reassembled before Sip Parser for better extraction of information. The following are the headers from where Sip parser extracts information.

- Request
- To
- From
- Call-ID
- Cell-ID
- M (Media information SDP)
- C (Connection information SDP)

## Generated Output:
The output is in the form of a struct containing the following information.
- REQ
  - Method (Sip Method eg INVITE etc)
  - StatusCode (Status Code eg 100)
  - Src (Full source)
- FROM
  - UriType (Type of URI sip, sips, tel, etc)
  - User (User part)
  - Src ( Full source)
- TO
  - UriType (Type of URI sip, sips, tel, etc)
  - User (User part)
  - Src ( Full source)
- Call-ID
  - Value (Call-ID Value)
  - Src (Full source)
- Cell-ID
  - Value (Cell-ID Value)
  - Src (Full source)
- MediaDesc
  - MediaType (Named portion of URI)
  - Port (Port number)
  - Src (Full source if needed)
- ConnData
  - AddrType (Address Type)
  - ConnAddr (Connection Address)
  - Src (Full source if needed)
