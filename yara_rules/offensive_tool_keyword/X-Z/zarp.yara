rule zarp
{
    meta:
        description = "Detection patterns for the tool 'zarp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zarp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A network attack framework.
        // Reference: https://github.com/hatRiot/zarp
        $string1 = /zarp\.py/ nocase ascii wide

    condition:
        any of them
}
