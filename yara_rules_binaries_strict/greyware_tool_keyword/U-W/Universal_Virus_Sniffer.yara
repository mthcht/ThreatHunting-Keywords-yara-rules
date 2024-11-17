rule Universal_Virus_Sniffer
{
    meta:
        description = "Detection patterns for the tool 'Universal Virus Sniffer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Universal Virus Sniffer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string1 = /\/uvs_v415eng\.zip/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string2 = /\\AppData\\Local\\Temp\\.{0,100}\\Doc_ENG\\_Rootkit\sdetection\.txt/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string3 = /\\Update_UVS\.exe/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string4 = /\\uvs_v415eng\.zip/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string5 = /dd90d845a111bc52b3d81dd597c5eaf0ef41d2278383a668f8932d8faefccbda/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string6 = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_freeupdate_en\.htm/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string7 = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_register_en\.htm/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string8 = /PUA\.Win32\.uVirusSniffer\.A/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string9 = /PUA\:Win32\/Packunwan/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string10 = /Universal\.Virus\.Sniffer\.4\.15\.zip/ nocase ascii wide
        // Description: Universal Virus Sniffer detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/universal_virus_sniffer.html
        $string11 = /Win32\/UniversalVirusSniffer/ nocase ascii wide
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
