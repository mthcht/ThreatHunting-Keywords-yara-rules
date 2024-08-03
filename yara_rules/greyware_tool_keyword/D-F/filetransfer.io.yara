rule filetransfer_io
{
    meta:
        description = "Detection patterns for the tool 'filetransfer.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "filetransfer.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: uploading to filetransfer.io
        // Reference: https://filetransfer.io
        $string1 = /filetransfer\.io\/upload\// nocase ascii wide

    condition:
        any of them
}
