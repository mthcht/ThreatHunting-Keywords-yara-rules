rule Bomgar
{
    meta:
        description = "Detection patterns for the tool 'Bomgar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bomgar"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string1 = /\.beyondtrustcloud\.com\/session_complete/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string2 = /\/bomgar\-rep\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string3 = /\/bomgar\-rep\-installer\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string4 = /\/bomgar\-scc\-.{0,100}\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string5 = /\/bomgar\-scc\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string6 = /\\appdata\\local\\bomgar\\bomgar\-rep\\/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string7 = /\\Bomgar\-enum_cp\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string8 = /\\bomgar\-rep\.cache\\/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string9 = /\\bomgar\-rep\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string10 = /\\bomgar\-rep\-installer\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string11 = /\\bomgar\-scc\-.{0,100}\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string12 = /\\bomgar\-scc\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string13 = /\\BOMGAR\-SCC\.EXE\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string14 = /\\cbhook\-x86\.dll/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string15 = /\\CurrentVersion\\Run\\Bomgar\sSupport\sReconnect/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string16 = /\\CurrentVersion\\Uninstall\\Representative\sConsole\s\[eval\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string17 = /\\embedhook\-x64\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string18 = /\\embedhook\-x86\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string19 = /\\programdata\\bomgar\-scc\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string20 = ">Bomgar Corporation</Data>" nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string21 = ">Remote Support Customer Client</Data>" nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string22 = ">Representative Console</Data>" nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string23 = /beyondtrustcloud\.com\\Software\\Qt6/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string24 = /bomgar\-rdp\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string25 = "'Company'>BeyondTrust</Data>" nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string26 = "'Company'>bomgar</Data>" nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string27 = /eval\-.{0,100}\.beyondtrustcloud\.com/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string28 = /license\.bomgar\.com/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string29 = /\'TaskName\'\>\\Bomgar\sTask\s/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string30 = /To\:\sAll\sRepresentatives\s\sFrom\:\sRemote\sSupport\s.{0,100}\shas\sadded\sa\snote\sto\sthis\ssession\./ nocase ascii wide
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
