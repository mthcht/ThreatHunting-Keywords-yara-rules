rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string1 = /\/PCHunter\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string2 = /\/PCHunter_free\.zip/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string3 = /\\AppData\\Local\\Temp\\PCHunter\.sys/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string4 = /\\ControlSet001\\Services\\PCHunter/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string5 = /\\PCHunter\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string6 = /\\PCHunter_free\.zip/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string7 = /\\PCHunter64ar\.sys/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string8 = /\>Epoolsoft\sWindows\sInformation\sView\sTools\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string9 = /\>PC\sHunter\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string10 = /\>PCHunter\.sys\</ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string11 = /648eaadf2d81af9ea6792d48740aa3ef4787303f95a0e2abaf23b87b13758eb7/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string12 = /http\:\/\/www\.epoolsoft\.com\/pchunter\/pchunter_free/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string13 = /http\:\/\/www\.epoolsoft\.com\/PCHunter_Standard/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string14 = /https\:\/\/www\.majorgeeks\.com\/files\/details\/pc_hunter\.html/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string15 = /PCHunter32\.exe/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It?s designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string16 = /PCHunter64\.exe/ nocase ascii wide

    condition:
        any of them
}