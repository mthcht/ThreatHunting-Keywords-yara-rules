rule DriverDump
{
    meta:
        description = "Detection patterns for the tool 'DriverDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DriverDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\/DriverDump\.exe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = "/POC/driverdump/" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\\DriverDump\.c/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\\DriverDump\.exe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\\DriverDump\.sln/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\DriverDump\.vcxproj/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\nanodump\.c/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = "4f3632bb0c4eb05c443535dd3a773f83b3ac47f20ba75fbc3a2c8e6b80a46c60" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = "5b3811e463d5b424593910cbf7fd06218e993f8399a9add27b053f98bc984587" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = "7f005c1ea9c2021b5db5807fdf9e8e9f502b28f089ff17dc85b7d480a3e3d143" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = "83DF0D0B-8FC6-4BCA-9982-4D26523515A2" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = "c7600f446daa53037a63ad765e0873a9c45adfd8944e5fee1c1586936ecf2928" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = "Data Name=\"ServiceName\">procexp</Data>" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = "L\"NanoDumpPwd\"" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = "NanoDumpPPLmedicPipe" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = "NanoDumpSSPPipe" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = "pypykatz lsa minidump" nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string18 = /SYSTEM\\CurrentControlSet\\Services\\procexp/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string19 = "The nanodump was created succesfully" nocase ascii wide
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
