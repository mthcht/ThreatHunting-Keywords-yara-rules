rule MalSCCM
{
    meta:
        description = "Detection patterns for the tool 'MalSCCM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MalSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string1 = /\.exe\sapp\s\/create\s\/name\:.{0,100}\s\/uncpath\:.{0,100}\\\\/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string2 = /\.exe\sapp\s\/deploy\s\/name\:.{0,100}\s\/groupname\:.{0,100}\s\/assignmentname\:/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string3 = /\/MalSCCM\.git/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string4 = /\/MalSCCM\.sln/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string5 = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string6 = "Action: Locating SCCM Management Servers" nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string7 = "Action: Locating SCCM Servers in Registry" nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string8 = /MalSCCM\.exe/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string9 = "MalSCCM-main" nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string10 = "nettitude/MalSCCM" nocase ascii wide
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
