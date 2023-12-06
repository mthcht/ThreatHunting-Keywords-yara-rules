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
        $string1 = /\sEventViewer\-UACBypass/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string2 = /\/EventViewer\-UACBypass/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string3 = /\\EventViewer\-UACBypass/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string4 = /\\Windows\\Tasks\\p4yl0ad/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string5 = /EventViewerRCE\.ps1/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string6 = /Invoke\-EventViewer\s.{0,1000}\.exe/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string7 = /Invoke\-EventViewer\.ps1/ nocase ascii wide
        // Description: RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass
        // Reference: https://github.com/CsEnox/EventViewer-UACBypass
        $string8 = /OgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABFAHYAZQBuAHQAVgBpAGUAdwBlAHIAUgBDAEUALgBwAHMAMQA\=/ nocase ascii wide

    condition:
        any of them
}
