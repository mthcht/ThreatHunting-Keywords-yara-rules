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
        $string1 = /.{0,1000}\snetscan\.exe\s.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /.{0,1000}\.exe\s.{0,1000}\s\/hide\s.{0,1000}\s\/range:.{0,1000}\s\/auto:.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3 = /.{0,1000}\.exe\s\/wakeall.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4 = /.{0,1000}\/netscan\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5 = /.{0,1000}\/netscan_linux\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6 = /.{0,1000}\/netscan_portable\.zip.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string7 = /.{0,1000}\/netscan_setup\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string8 = /.{0,1000}\\netscan\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string9 = /.{0,1000}\\netscan_linux\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string10 = /.{0,1000}\\netscan_portable\.zip.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string11 = /.{0,1000}\\netscan_portable\\.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string12 = /.{0,1000}\\netscan_setup\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string13 = /.{0,1000}netscan\.exe\s\/.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string14 = /.{0,1000}SoftPerfect_.{0,1000}Patch_Keygen_v2.{0,1000}\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
