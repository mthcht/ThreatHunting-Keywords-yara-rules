rule reapoc
{
    meta:
        description = "Detection patterns for the tool 'reapoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reapoc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OpenSource Poc && Vulnerable-Target Storage Box.
        // Reference: https://github.com/cckuailong/reapoc
        $string1 = /.{0,1000}cckuailong\/reapoc.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
