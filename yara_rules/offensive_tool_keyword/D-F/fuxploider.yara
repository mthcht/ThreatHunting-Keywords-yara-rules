rule fuxploider
{
    meta:
        description = "Detection patterns for the tool 'fuxploider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuxploider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fuxploider is an open source penetration testing tool that automates the process of detecting and exploiting file upload forms flaws. This tool is able to detect the file types allowed to be uploaded and is able to detect which technique will work best to upload web shells or any malicious file on the desired web server.
        // Reference: https://github.com/almandin/fuxploider
        $string1 = /fuxploider/ nocase ascii wide

    condition:
        any of them
}
