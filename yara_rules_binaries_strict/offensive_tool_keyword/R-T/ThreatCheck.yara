rule ThreatCheck
{
    meta:
        description = "Detection patterns for the tool 'ThreatCheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreatCheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string1 = /\s\-f\s.{0,100}\.bin\s\-e\sAMSI/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string2 = /\s\-f\s.{0,100}\.bin\s\-e\sDefender/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string3 = /\s\-Scan\s\-ScanType\s3\s\-File\s.{0,100}\s\-DisableRemediation\s\-Trace\s\-Level\s0x10/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string4 = /\/ThreatCheck\.git/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string5 = /\\Blackout\.sys/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string6 = /\\NimBlackout/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string7 = /3EC9B9A8\-0AFE\-44A7\-8B95\-7F60E750F042/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string8 = /76f677acfe19ca1e1e39c391e4923dc38e1e3f752097c5808c171c1d5228194e/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string9 = /C\:\\Temp\\file\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string10 = /NimBlackout.{0,100}\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string11 = /NimBlackout\./ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string12 = /NimBlackout\-main/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string13 = /rasta\-mouse\/ThreatCheck/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string14 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string15 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string16 = /ThreatCheck\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string17 = /ThreatCheck\-master/ nocase ascii wide
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
