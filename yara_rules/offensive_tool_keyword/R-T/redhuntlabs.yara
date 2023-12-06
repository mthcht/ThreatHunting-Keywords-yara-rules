rule redhuntlabs
{
    meta:
        description = "Detection patterns for the tool 'redhuntlabs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redhuntlabs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: documentation for offensive operation
        // Reference: https://github.com/redhuntlabs
        $string1 = /redhuntlabs/ nocase ascii wide

    condition:
        any of them
}
