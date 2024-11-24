rule EarthWorm
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "signature_keyword"

    strings:
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string1 = "ELF:Earthworm-B" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string2 = /HackTool\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string3 = /Hacktool\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string4 = /HackTool\.Linux\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string5 = /HackTool\.Win32\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string6 = /HackTool\/Win32\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string7 = "HackTool:Linux/EarthWorm" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string8 = /Linux\.Hacktool\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string9 = /Tool\.Linux\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string10 = /Win\.Tool\.Earthworm\-/ nocase ascii wide
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
