rule hack_tools
{
    meta:
        description = "Detection patterns for the tool 'hack-tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hack-tools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string1 = /\/Hack\-Tools\.git/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string2 = /cmbndhnoonmghfofefkcccljbkdpamhi_14678\.crx/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string3 = /hacktools\-.{0,1000}\.xpi/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string4 = /hack\-tools\/cmbndhnoonmghfofefkcccljbkdpamhi/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string5 = /Hack\-Tools\-master/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string6 = /https\:\/\/crackstation\.net\// nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string7 = /LasCC\/Hack\-Tools/ nocase ascii wide

    condition:
        any of them
}
