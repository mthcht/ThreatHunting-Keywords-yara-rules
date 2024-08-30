rule TDSKiller
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string1 = /\/TDSSKiller\.exe/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string2 = /\/tdsskiller\.zip/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string3 = /\\TDSSKiller\.exe/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string4 = /\\tdsskiller\.zip/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string5 = /\>TDSS\srootkit\sremoving\stool\</ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string6 = /\>TDSSKiller\</ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string7 = /2d823c8b6076e932d696e8cb8a2c5c5df6d392526cba8e39b64c43635f683009/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string8 = /http\:\/\/support\.kaspersky\.com\/viruses\/tdsskiller\.xmlt/ nocase ascii wide

    condition:
        any of them
}
