rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "signature_keyword"

    strings:
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string1 = /PUA\.Win64\.PCHunter\.YACIU/ nocase ascii wide
        // Description: PCHunter is a toolkit offering deep access to kernel setting - processes - network  and startup configurations. It is designed to detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/pc_hunter.html
        $string2 = /RiskWare\.PcHunter/ nocase ascii wide

    condition:
        any of them
}
