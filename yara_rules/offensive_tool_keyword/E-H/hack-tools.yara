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
        $string1 = /.{0,1000}\/Hack\-Tools\.git.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string2 = /.{0,1000}cmbndhnoonmghfofefkcccljbkdpamhi_14678\.crx.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string3 = /.{0,1000}hacktools\-.{0,1000}\.xpi.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string4 = /.{0,1000}hack\-tools\/cmbndhnoonmghfofefkcccljbkdpamhi.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string5 = /.{0,1000}Hack\-Tools\-master.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string6 = /.{0,1000}https:\/\/crackstation\.net\/.{0,1000}/ nocase ascii wide
        // Description: The all-in-one Red Team browser extension for Web Pentester
        // Reference: https://github.com/LasCC/Hack-Tools
        $string7 = /.{0,1000}LasCC\/Hack\-Tools.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
