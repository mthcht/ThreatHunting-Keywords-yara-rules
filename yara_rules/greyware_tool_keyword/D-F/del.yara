rule del
{
    meta:
        description = "Detection patterns for the tool 'del' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "del"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious deletion made by the Russian Foreign Intelligence Service
        // Reference: https://github.com/mthcht/ThreatIntel-Reports
        $string1 = /\sdel\sC\:\\Windows\\temp\\1\s\/F\s\/Q/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /del\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = "del /f /s /q /a %AppData%" nocase ascii wide
        // Description: removes the Default.rdp file likely to erase evidence of RDP connections
        // Reference: https://github.com/xiaoy-sec/Pentest_Note/blob/52156f816f0c2497c25343c2e872130193acca80/wiki/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/Windows%E6%8F%90%E6%9D%83/RDP%26Firewall/%E5%88%A0%E9%99%A4%E7%97%95%E8%BF%B9.md?plain=1#L4
        $string4 = /del\sDefault\.rdp/ nocase ascii wide

    condition:
        any of them
}
