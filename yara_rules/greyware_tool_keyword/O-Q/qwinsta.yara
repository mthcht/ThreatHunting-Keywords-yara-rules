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
        $string1 = /.{0,1000}qwinsta\s\/server:.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
