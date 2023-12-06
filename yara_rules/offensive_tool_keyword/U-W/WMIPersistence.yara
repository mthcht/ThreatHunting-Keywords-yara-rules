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
        $string1 = /WMIPersist\./ nocase ascii wide

    condition:
        any of them
}
