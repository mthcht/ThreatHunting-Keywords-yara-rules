rule sniffer
{
    meta:
        description = "Detection patterns for the tool 'sniffer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string1 = /.{0,1000}\/sniffer\.git.{0,1000}/ nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string2 = /.{0,1000}brew\sinstall\ssniffer.{0,1000}/ nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string3 = /.{0,1000}chenjiandongx\/sniffer.{0,1000}/ nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string4 = /.{0,1000}sniffer\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string5 = /sniffer\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
