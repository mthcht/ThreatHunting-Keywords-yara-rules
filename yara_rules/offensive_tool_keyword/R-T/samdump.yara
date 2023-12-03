rule samdump
{
    meta:
        description = "Detection patterns for the tool 'samdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping sam
        // Reference: https://github.com/nyxgeek/classic_hacking_tools
        $string1 = /.{0,1000}samdump\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
