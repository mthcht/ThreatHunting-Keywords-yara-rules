rule UniversalDVC
{
    meta:
        description = "Detection patterns for the tool 'UniversalDVC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UniversalDVC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: run an executable (UDVC-Server.exe) that sets up a communication channel for redirecting an SSF port using a DVC server. This can be seen as a form of proxy to evade detection or bypass network restrictions.
        // Reference: https://github.com/earthquake/UniversalDVC
        $string1 = /.{0,1000}UDVC\-Server\.exe\s\-c\s.{0,1000}\s\-i\s127\.0\.0\.1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
