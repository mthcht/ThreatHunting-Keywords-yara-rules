rule softperfect_networkscanner
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "signature_keyword"

    strings:
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string1 = /\sWin64\/NetTool\.SoftPerfectNetscan/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /Hacktool\.SoftPerfectNetscan/ nocase ascii wide

    condition:
        any of them
}
