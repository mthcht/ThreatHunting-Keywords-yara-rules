rule SecScanC2
{
    meta:
        description = "Detection patterns for the tool 'SecScanC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecScanC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string1 = /\/listProxyPool\?k\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string2 = /\/SecScanC2\.git/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string3 = /\/shell\?k\=.{0,100}\&ip\=.{0,100}\&cmd\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string4 = /\/startProxyPool\?k\=.{0,100}\&random\=n\&number\=2\&ip\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string5 = /\/startProxyPool\?k\=.{0,100}\&random\=y\&number\=2/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string6 = "AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363" nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string7 = "SecScanC2_admin " nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string8 = "SecScanC2_admin_" nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string9 = "SecScanC2_node " nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string10 = "SecScanC2_node_" nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string11 = "SecScanC2-main" nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string12 = "T1esh0u/SecScanC2" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
