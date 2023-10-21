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
        $string1 = /\snetscan\.exe\s/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /\.exe\s.*\s\/hide\s.*\s\/range:.*\s\/auto:.*\./ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3 = /\.exe\s\/wakeall/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4 = /\/netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5 = /\/netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6 = /\/netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string7 = /\/netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string8 = /\\netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string9 = /\\netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string10 = /\\netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string11 = /\\netscan_portable\\/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string12 = /\\netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string13 = /netscan\.exe\s\// nocase ascii wide

    condition:
        any of them
}