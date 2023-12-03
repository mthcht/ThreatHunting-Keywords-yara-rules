rule wpaf
{
    meta:
        description = "Detection patterns for the tool 'wpaf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wpaf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WordPress admin finder
        // Reference: https://github.com/kancotdiq/wpaf
        $string1 = /.{0,1000}\/wpaf\/finder\.py.{0,1000}/ nocase ascii wide
        // Description: WordPress admin finder
        // Reference: https://github.com/kancotdiq/wpaf
        $string2 = /.{0,1000}kancotdiq\/wpaf.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
