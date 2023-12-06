rule ntlmquic
{
    meta:
        description = "Detection patterns for the tool 'ntlmquic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmquic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string1 = /\/ntlmquic/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string2 = /\/quicserver\.exe/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string3 = /msquic_openssl\/msquic\.dll/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string4 = /msquic_openssl\/msquic\.lib/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string5 = /ntlmquic\./ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string6 = /ntlmquic\-go/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string7 = /ntlmquic\-master/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string8 = /xcopy\s\/y\s\/d\s\s.{0,1000}\\msquic_schannel\\msquic\.dll/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string9 = /xpn.{0,1000}ntlmquic/ nocase ascii wide

    condition:
        any of them
}
