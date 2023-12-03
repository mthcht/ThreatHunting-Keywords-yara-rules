rule nltest
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string1 = /.{0,1000}nltest\s\/all_trusts.{0,1000}/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string2 = /.{0,1000}nltest\s\/dclist.{0,1000}/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string3 = /.{0,1000}nltest\s\/domain_trusts.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
