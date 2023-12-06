rule upload_nolog_cz
{
    meta:
        description = "Detection patterns for the tool 'upload.nolog.cz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "upload.nolog.cz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: sharing platform
        // Reference: https://upload.nolog.cz/
        $string1 = /upload\.nolog\.cz/ nocase ascii wide

    condition:
        any of them
}
