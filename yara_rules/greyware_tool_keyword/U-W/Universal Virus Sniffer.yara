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
        $string2 = /\\AppData\\Local\\Temp\\.{0,1000}\\Doc_ENG\\_Rootkit\sdetection\.txt/ nocase ascii wide
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

    condition:
        any of them
}
