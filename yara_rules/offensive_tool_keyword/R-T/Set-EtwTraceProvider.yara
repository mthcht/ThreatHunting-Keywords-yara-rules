rule Set_EtwTraceProvider
{
    meta:
        description = "Detection patterns for the tool 'Set-EtwTraceProvider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Set-EtwTraceProvider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: disables Microsoft-Windows-PowerShell event logging
        // Reference: N/A
        $string1 = /Set\-EtwTraceProvider\s\-Guid\s\'\{A0C1853B\-5C40\-4B15\-8766\-3CF1C58F985A\}\'\s\-AutologgerName\s\'EventLog\-Application\'\s\-Property\s0x11/ nocase ascii wide

    condition:
        any of them
}
