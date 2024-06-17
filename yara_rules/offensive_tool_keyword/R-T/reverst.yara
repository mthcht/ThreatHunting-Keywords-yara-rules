rule reverst
{
    meta:
        description = "Detection patterns for the tool 'reverst' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverst"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string1 = /\s\-\-http\-address\s127\.0\.0\.1\:8181/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string2 = /\s\-\-tunnel\-address\s127\.0\.0\.1\:7171/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string3 = /\.reverst\.tunnel\:/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string4 = /\/cmd\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string5 = /\/etc\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string6 = /\/etc\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string7 = /\/quic\-go\/quic\-go\/http3/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string8 = /\/reverst\.git/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string9 = /\/reverst\.git/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string10 = /\/usr\/local\/bin\/reverst/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string11 = /\/usr\/local\/bin\/reverst/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string12 = /1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string13 = /1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string14 = /Bearer\sc29tZWludmFsaWQ6Y29tYmluYXRpb24\=/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string15 = /flipt\-io\/reverst/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string16 = /flipt\-io\/reverst/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string17 = /go\srun\s\.\/cmd\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string18 = /go\.flipt\.io\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string19 = /go\.flipt\.io\/reverst\// nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string20 = /reverst\s.{0,1000}\-\-tunnel\-address\s/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string21 = /REVERST_CERTIFICATE_PATH/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string22 = /REVERST_LOG/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string23 = /REVERST_PRIVATE_KEY_PATH/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string24 = /REVERST_SERVER_NAME/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string25 = /REVERST_TUNNEL_ADDRESS/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string26 = /REVERST_TUNNEL_GROUPS/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string27 = /ZXZpbG1vcnR5Om11bHRpdmVyc2U\=/ nocase ascii wide

    condition:
        any of them
}
