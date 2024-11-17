rule C2ReverseProxy
{
    meta:
        description = "Detection patterns for the tool 'C2ReverseProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2ReverseProxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1 = /\/C2ReverseProxy\.git/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string2 = /\/C2ReverseProxy\// nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string3 = /\/C2ReverseProxy\/tarball/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string4 = /\/C2ReverseProxy\/zipball/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string5 = /\/C2ReverseServer/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string6 = /\/DReverseProxy\.git/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string7 = /\\C2ReverseProxy\\/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string8 = /\\C2ReverseServer/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string9 = /\\C2script\\.{0,100}\.ashx/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string10 = /\\C2script\\.{0,100}\.jsp/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string11 = /\\C2script\\.{0,100}\.php/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string12 = /\\DReverseClint\.go/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string13 = /\\DReverseServer\.go/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string14 = /0c3379e3cc4fab5cbf1ce0aff52559da191a2b97c6fa27d5122232649f78e7cc/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string15 = /512e079176dfe039a4692927ad7fbe518c944c28bb434add1118fef88a48029c/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string16 = /a0595728f0d3fbcc2cb434ad9af104158c349cc05a360e037ee027529bde97d1/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string17 = /c2\starget\,eg\s127\.0\.0\.1\:64535/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string18 = /Daybr4ak\/C2ReverseProxy/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string19 = /f2c1234d05744b49749b6ef743d7a71a45d96400ec1b510531032de8312a377d/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string20 = /f94f938826dab5d26488e0bc6f5aa8e9eed3a395d1e9a0c9f2a49d877ea56225/ nocase ascii wide
        // Description: ReverseProxy C2 - Bring CS online without going offline
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string21 = /http\:\/\/127\.0\.0\.1\/proxy\.php/ nocase ascii wide
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
