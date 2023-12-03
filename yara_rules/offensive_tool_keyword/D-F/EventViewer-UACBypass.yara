rule EventViewer_UACBypass
{
    meta:
        description = "Detection patterns for the tool 'EventViewer-UACBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventViewer-UACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string1 = /.{0,1000}\sEventViewer\-UACBypass.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string2 = /.{0,1000}\/EventViewer\-UACBypass.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string3 = /.{0,1000}\\EventViewer\-UACBypass.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string4 = /.{0,1000}\\Windows\\Tasks\\p4yl0ad.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string5 = /.{0,1000}EventViewerRCE\.ps1.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string6 = /.{0,1000}Invoke\-EventViewer\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string7 = /.{0,1000}Invoke\-EventViewer\.ps1.{0,1000}/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string8 = /.{0,1000}OgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABFAHYAZQBuAHQAVgBpAGUAdwBlAHIAUgBDAEUALgBwAHMAMQA\=.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
