rule aeroadmin
{
    meta:
        description = "Detection patterns for the tool 'aeroadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aeroadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string1 = /\saeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string2 = /\/aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string3 = /\\AeroAdmin\s.{0,100}_Portable\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string4 = /\\aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string5 = /\\Aeroadmin\.lnk/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string6 = /\\Aeroadmin\\black\.bmp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string7 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string8 = /\\CurrentControlSet\\Services\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string9 = /\\InventoryApplicationFile\\aeroadmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string10 = /\\ProgramData\\Aeroadmin\\/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string11 = "2ef8a13faa44755fab1ac6fb3665cc78f7e7b451" nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string12 = "Aeroadmin LLC" nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string13 = /AeroAdmin\sPRO\s\-\sremote\sdesktop\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string14 = /AeroAdmin\sPRO\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string15 = /AeroAdmin\sv4\..{0,100}\s\(/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string16 = /AeroAdmin\.cpp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string17 = /AEROADMIN\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string18 = /Aeroadmin\\Screenshots/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string19 = /AeroAdmin_2\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string20 = "AeroadminService" nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string21 = /auth.{0,100}\.aeroadmin\.com/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string22 = /auth11\.aeroadmin\.com/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string23 = /DEFAULT\\Software\\AeroAdmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string24 = "EE54577067550559C4711C9E5E10435807F9DEEE9A5ADB4409CB60A6B0108700" nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string25 = /ulm\.aeroadmin\.com\// nocase ascii wide
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
