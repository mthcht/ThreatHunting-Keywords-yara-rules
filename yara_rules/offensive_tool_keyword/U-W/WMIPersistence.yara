rule WMIPersistence
{
    meta:
        description = "Detection patterns for the tool 'WMIPersistence' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIPersistence"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An example of how to perform WMI Event Subscription persistence using C#
        // Reference: https://github.com/mdsecactivebreach/WMIPersistence
        $string1 = /\/WMIPersistence\.git/ nocase ascii wide
        // Description: An example of how to perform WMI Event Subscription persistence using C#
        // Reference: https://github.com/mdsecactivebreach/WMIPersistence
        $string2 = /b236ff16fc6a017c5a84d0cc7969e0513636f37058b2b74a95d632ea26953586/ nocase ascii wide
        // Description: An example of how to perform WMI Event Subscription persistence using C#
        // Reference: https://github.com/mdsecactivebreach/WMIPersistence
        $string3 = /mdsecactivebreach\/WMIPersistence/ nocase ascii wide
        // Description: An example of how to perform WMI Event Subscription persistence using C#
        // Reference: https://github.com/mdsecactivebreach/WMIPersistence
        $string4 = /WMIPersist\./ nocase ascii wide

    condition:
        any of them
}
