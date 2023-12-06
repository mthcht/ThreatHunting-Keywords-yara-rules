rule ridrelay
{
    meta:
        description = "Detection patterns for the tool 'ridrelay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ridrelay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quick and easy way to get domain usernames while on an internal network.
        // Reference: https://github.com/skorov/ridrelay
        $string1 = /ridrelay/ nocase ascii wide

    condition:
        any of them
}
