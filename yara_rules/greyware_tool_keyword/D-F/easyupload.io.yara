rule easyupload_io
{
    meta:
        description = "Detection patterns for the tool 'easyupload.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "easyupload.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: hosting platform abused by attackers
        // Reference: N/A
        $string1 = /https\:\/\/easyupload\.io\/action\.php/ nocase ascii wide
        // Description: hosting platform abused by attackers
        // Reference: N/A
        $string2 = /https\:\/\/easyupload\.io\/cdn\-cgi\/rum/ nocase ascii wide

    condition:
        any of them
}
