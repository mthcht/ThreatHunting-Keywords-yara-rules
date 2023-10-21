rule WSUSpendu
{
    meta:
        description = "Detection patterns for the tool 'WSUSpendu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSUSpendu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: At BlackHat USA 2015. the WSUSpect attack scenario has been released.Approximately at the same time. some french engineers have been wondering if it would be possible to use a compromised WSUS server to extend the compromise to its clients. similarly to this WSUSpect attack. After letting this topic rest for almost two years. we've been able. at Alsid and ANSSI. to demonstrate this attack.
        // Reference: https://github.com/AlsidOfficial/WSUSpendu
        $string1 = /WSUSpendu/ nocase ascii wide

    condition:
        any of them
}