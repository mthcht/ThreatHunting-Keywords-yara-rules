rule ren
{
    meta:
        description = "Detection patterns for the tool 'ren' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ren"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string1 = /ren\sC:\\Windows\\System32\\amsi\.dll\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
