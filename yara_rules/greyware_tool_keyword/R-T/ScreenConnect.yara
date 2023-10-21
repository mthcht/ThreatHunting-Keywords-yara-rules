rule ScreenConnect
{
    meta:
        description = "Detection patterns for the tool 'ScreenConnect' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScreenConnect"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string1 = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string2 = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string3 = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string4 = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string5 = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string6 = /\\TEMP\\ScreenConnect\\.*\.ps1/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string7 = /cmd\.exe.*\\TEMP\\ScreenConnect\\.*\.cmd/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string8 = /https:\/\/.*\.screenconnect\.com\/Bin\/.*\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string9 = /server.*\-relay\.screenconnect\.com/ nocase ascii wide

    condition:
        any of them
}