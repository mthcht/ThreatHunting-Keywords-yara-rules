rule backdoor_keyword
{
    meta:
        description = "Detection patterns for the tool 'backdoor keyword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "backdoor keyword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keyword observed in multiple backdoor tools
        // Reference: N/A
        $string1 = /Backdoor\./ nocase ascii wide

    condition:
        any of them
}