rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string1 = /\/PCHunter\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string2 = /\/PCHunter_free\.zip/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string3 = /\\AppData\\Local\\Temp\\PCHunter\.sys/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string4 = /\\ControlSet001\\Services\\PCHunter/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string5 = /\\PCHunter\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string6 = /\\PCHunter_free\.zip/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string7 = /\\PCHunter32\.pdb/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string8 = /\\PCHunter64ar\.sys/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string9 = /\>Epoolsoft\sWindows\sInformation\sView\sTools\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string10 = /\>PC\sHunter\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string11 = /\>PCHunter\.sys\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string12 = /648eaadf2d81af9ea6792d48740aa3ef4787303f95a0e2abaf23b87b13758eb7/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string13 = /http\:\/\/www\.epoolsoft\.com\/pchunter\/pchunter_free/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string14 = /http\:\/\/www\.epoolsoft\.com\/PCHunter_Standard/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string15 = /https\:\/\/www\.majorgeeks\.com\/files\/details\/pc_hunter\.html/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string16 = /PC\sHunter\sStandard/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string17 = /PCHunter32\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string18 = /PCHunter64\.exe/ nocase ascii wide
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
