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
        $string1 = /.{0,1000}\/ntlmquic.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string2 = /.{0,1000}\/quicserver\.exe.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string3 = /.{0,1000}msquic_openssl\/msquic\.dll.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string4 = /.{0,1000}msquic_openssl\/msquic\.lib.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string5 = /.{0,1000}ntlmquic\..{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string6 = /.{0,1000}ntlmquic\-go.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string7 = /.{0,1000}ntlmquic\-master.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string8 = /.{0,1000}xcopy\s\/y\s\/d\s\s.{0,1000}\\msquic_schannel\\msquic\.dll.{0,1000}/ nocase ascii wide
        // Description: POC tools for exploring SMB over QUIC protocol
        // Reference: https://github.com/xpn/ntlmquic
        $string9 = /.{0,1000}xpn.{0,1000}ntlmquic.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
