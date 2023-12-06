rule passwd
{
    meta:
        description = "Detection patterns for the tool 'passwd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1 = /passwd.{0,1000}john/ nocase ascii wide

    condition:
        any of them
}
