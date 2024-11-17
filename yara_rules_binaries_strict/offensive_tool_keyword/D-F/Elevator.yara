rule Elevator
{
    meta:
        description = "Detection patterns for the tool 'Elevator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Elevator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string1 = /\/Elevator\.git/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string2 = /\[\!\]\sElevated\sprocess\sspawned\!/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string3 = /\\elevator\.exe\s\-/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string4 = /\\Elevator\\target\\release/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string5 = /73415a38d4b76dd2215d9fd81015b36a025018552f7847494f908f50c62fc8d2/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string6 = /AAB75969\-92BA\-4632\-9F78\-AF52FA2BCE1E/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string7 = /elevator\.exe\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string8 = /Kudaes\/Elevator/ nocase ascii wide
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
