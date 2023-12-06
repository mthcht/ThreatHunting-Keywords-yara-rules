rule unshadow
{
    meta:
        description = "Detection patterns for the tool 'unshadow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshadow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1 = /unshadow\spasswd\sshadow\s\>\s/ nocase ascii wide

    condition:
        any of them
}
