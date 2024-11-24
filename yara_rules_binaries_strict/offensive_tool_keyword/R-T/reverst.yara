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
        $string4 = "/cmd/reverst/" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string5 = "/etc/reverst/" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string6 = "/etc/reverst/" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string7 = "/quic-go/quic-go/http3" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string8 = /\/reverst\.git/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string9 = /\/reverst\.git/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string10 = "/usr/local/bin/reverst" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string11 = "/usr/local/bin/reverst" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string12 = "1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string13 = "1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string14 = "Bearer c29tZWludmFsaWQ6Y29tYmluYXRpb24=" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string15 = "flipt-io/reverst" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string16 = "flipt-io/reverst" nocase ascii wide
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
        $string20 = /reverst\s.{0,100}\-\-tunnel\-address\s/ nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string21 = "REVERST_CERTIFICATE_PATH" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string22 = "REVERST_LOG" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string23 = "REVERST_PRIVATE_KEY_PATH" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string24 = "REVERST_SERVER_NAME" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string25 = "REVERST_TUNNEL_ADDRESS" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string26 = "REVERST_TUNNEL_GROUPS" nocase ascii wide
        // Description: Reverse Tunnels in Go over HTTP/3 and QUIC
        // Reference: https://github.com/flipt-io/reverst
        $string27 = "ZXZpbG1vcnR5Om11bHRpdmVyc2U=" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
