rule tightvnc
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string1 = " -service TightVNC Server" nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string2 = /\.\\TightVNC1/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string3 = /\.\\TightVNC2/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string4 = /\.\\TightVNC3/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string5 = /\/tightvnc\-.{0,100}\.msi/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string6 = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string7 = /\\Programs\\TightVNC/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string8 = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string9 = /\\TightVNC\sServer/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string10 = /\\tightvnc\-/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string11 = /\\TightVNC_Service_Control/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string12 = /\\TVN_log_pipe_public_name/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string13 = ">TightVNC Viewer<" nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string14 = /00\:\\\.vnc\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string15 = /GlavSoft\sLLC\./ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string16 = /HKCR\\\.vnc/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string17 = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string18 = /ProgramData\\TightVNC/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string19 = "TightVNC Service" nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string20 = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string21 = "tvnserver" nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string22 = /tvnserver\.exe/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string23 = /tvnviewer\.exe/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string24 = /VncViewer\.Config/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string25 = /www\.tightvnc\.com\/download\/.{0,100}\=/ nocase ascii wide
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
