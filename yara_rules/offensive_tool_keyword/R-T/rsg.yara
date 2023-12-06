rule rsg
{
    meta:
        description = "Detection patterns for the tool 'rsg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to generate various ways to do a reverse shell
        // Reference: https://github.com/mthbernardes/rsg
        $string1 = /mthbernardes.{0,1000}rsg/ nocase ascii wide

    condition:
        any of them
}
