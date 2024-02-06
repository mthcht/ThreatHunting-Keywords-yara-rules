rule vncviewer
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1 = /vncviewer\s.{0,1000}\..{0,1000}\:5901/ nocase ascii wide

    condition:
        any of them
}
