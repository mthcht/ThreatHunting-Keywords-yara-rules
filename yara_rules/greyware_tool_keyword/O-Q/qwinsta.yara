rule qwinsta
{
    meta:
        description = "Detection patterns for the tool 'qwinsta' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qwinsta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate rdp session on a remote server
        // Reference: N/A
        $string1 = /cmd\s\/c\s.{0,1000}qwinsta/ nocase ascii wide
        // Description: enumerate rdp session on a remote server
        // Reference: N/A
        $string2 = /cmd\.exe.{0,1000}qwinsta/ nocase ascii wide
        // Description: enumerate rdp session on a remote server
        // Reference: N/A
        $string3 = /qwinsta\s\/server\:/ nocase ascii wide

    condition:
        any of them
}
