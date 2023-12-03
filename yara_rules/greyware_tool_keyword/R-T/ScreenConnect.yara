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
        $string1 = /.{0,1000}\\ScreenConnect\.Client\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string2 = /.{0,1000}\\ScreenConnect\.ClientService\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string3 = /.{0,1000}\\ScreenConnect\.ClientSetup\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string4 = /.{0,1000}\\ScreenConnect\.WindowsBackstageShell\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string5 = /.{0,1000}\\ScreenConnect\.WindowsClient\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string6 = /.{0,1000}\\TEMP\\ScreenConnect\\.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string7 = /.{0,1000}cmd\.exe.{0,1000}\\TEMP\\ScreenConnect\\.{0,1000}\.cmd.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string8 = /.{0,1000}https:\/\/.{0,1000}\.screenconnect\.com\/Bin\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string9 = /.{0,1000}server.{0,1000}\-relay\.screenconnect\.com.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
