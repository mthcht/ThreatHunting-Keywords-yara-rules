rule MSSprinkler
{
    meta:
        description = "Detection patterns for the tool 'MSSprinkler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSSprinkler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string1 = /\smssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string2 = /\s\-user\suserlist\.txt\s\-pass\spasswordlist\.txt\s/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string3 = /\/MSSprinkler\.git/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string4 = /\/mssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string5 = /\\mssprinkler\.ps1/ nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string6 = "c299346734b17df1a8dc47d97145c756938307fbd249837ff4dc697befd2961b" nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string7 = "Invoke-MSSprinkler" nocase ascii wide
        // Description: password spraying utility for organizations to test their M365 accounts from an external perspective. It employs a 'low-and-slow' approach
        // Reference: https://github.com/TheresAFewConors/MSSprinkler
        $string8 = "TheresAFewConors/MSSprinkler" nocase ascii wide
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
