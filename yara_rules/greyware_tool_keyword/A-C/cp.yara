rule cp
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1 = /cp\s\/etc\/passwd/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string2 = /cp\s\/etc\/shadow/ nocase ascii wide

    condition:
        any of them
}
