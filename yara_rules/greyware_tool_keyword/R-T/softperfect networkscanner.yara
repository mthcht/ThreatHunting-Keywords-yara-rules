rule softperfect_networkscanner
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string1 = /\s\/config:netscan\.xml\s/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /\snetscan\.exe\s/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3 = /\.exe\s.{0,1000}\s\/hide\s.{0,1000}\s\/range:.{0,1000}\s\/auto:.{0,1000}\./ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4 = /\.exe\s\/hide\s\/range:all/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5 = /\.exe\s\/wakeall/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6 = /\/netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string7 = /\/netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string8 = /\/netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string9 = /\/netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string10 = /\\netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string11 = /\\netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string12 = /\\netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string13 = /\\netscan_portable\\/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string14 = /\\netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string15 = /netscan\.exe\s\// nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string16 = /SoftPerfect_.{0,1000}Patch_Keygen_v2.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
