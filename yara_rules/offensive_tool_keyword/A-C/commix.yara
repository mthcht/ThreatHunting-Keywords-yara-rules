rule commix
{
    meta:
        description = "Detection patterns for the tool 'commix' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commix"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automated All-in-One OS command injection and exploitation tool.
        // Reference: https://github.com/commixproject/commix
        $string1 = /.{0,1000}\/commix\.git/ nocase ascii wide
        // Description: Automated All-in-One OS command injection and exploitation tool.
        // Reference: https://github.com/commixproject/commix
        $string2 = /.{0,1000}\/commix\.py.{0,1000}/ nocase ascii wide
        // Description: Automated All-in-One OS command injection and exploitation tool.
        // Reference: https://github.com/commixproject/commix
        $string3 = /.{0,1000}commixproject\/commix.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
