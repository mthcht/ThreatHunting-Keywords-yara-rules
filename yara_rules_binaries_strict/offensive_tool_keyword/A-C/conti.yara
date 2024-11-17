rule conti
{
    meta:
        description = "Detection patterns for the tool 'conti' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conti"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string1 = /\sC\:\\ProgramData\\sh\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string2 = /\sDriverName\s.{0,100}Xeroxxx/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string3 = /\/outfile\:C\:\\ProgramData\\hashes\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string4 = /\\ProgramData\\asrephashes\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string5 = /CVE\-2021\-34527\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string6 = /execute\-assembly\s.{0,100}asreproast/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string7 = /execute\-assembly\s.{0,100}kerberoast/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string8 = /HACKER.{0,100}FUCKER.{0,100}Xeroxxx/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string9 = /Invoke\-Nightmare\s\-DLL\s/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string10 = /Invoke\-Nightmare\s\-NewUser/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string11 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string12 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string13 = /ldapfilter\:.{0,100}admincount\=1.{0,100}\s\/format\:hashcat/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string14 = /net\sdomain_controllers/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string15 = /net\sgroup\s.{0,100}Enterprise\sAdmins.{0,100}\s\/dom/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string16 = /net\sgroup\s\/\sdomain\s.{0,100}Domain\sAdmins/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string17 = /powershell\-import.{0,100}Invoke\-Kerberoast\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string18 = /powershell\-import.{0,100}ShareFinder\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string19 = /psinject\s.{0,100}\sx64\sInvoke\-/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string20 = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s.{0,100}true/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string21 = /shell\snet\sgroup\s.{0,100}Domain\sComputers.{0,100}\s\/domain/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string22 = /shell\snet\slocalgroup\sadministrators/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string23 = /shell\snltest\s\/dclist/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string24 = /shell\srclone\.exe\scopy\s/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string25 = /shell\swhoami/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string26 = /spawnas\s.{0,100}\s\\\sHACKER\shttps/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string27 = /start\sPsExec\.exe\s\-d\s/ nocase ascii wide
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
