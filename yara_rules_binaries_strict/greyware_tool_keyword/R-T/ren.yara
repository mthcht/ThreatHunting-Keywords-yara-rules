rule ren
{
    meta:
        description = "Detection patterns for the tool 'ren' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ren"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string1 = /ren\sC\:\\Windows\\System32\\amsi\.dll\s.{0,100}\.dll/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string2 = /ren\ssethc\.exe\ssethcbad\.exe/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string3 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string4 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
        // Description: renaming some AV sys files - allows bypass
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = /ren\sSophosED\.sys\sSophosED\.sys\.old/ nocase ascii wide
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
