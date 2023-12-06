rule egressbuster
{
    meta:
        description = "Detection patterns for the tool 'egressbuster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "egressbuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EgressBuster is a way to test the effectiveness of egress filtering for an individual area. When performing a penetration test. often times companies leverage egress filtering in order to prevent access to the outside Internet. Most companies have special exceptions and allow ports but they may be difficult to find.
        // Reference: https://github.com/trustedsec/egressbuster
        $string1 = /egressbuster/ nocase ascii wide

    condition:
        any of them
}
