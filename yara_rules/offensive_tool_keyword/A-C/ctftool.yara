rule ctftool
{
    meta:
        description = "Detection patterns for the tool 'ctftool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ctftool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is ctftool. an interactive command line tool to experiment with CTF. a little-known protocol used on Windows to implement Text Services. This might be useful for studying Windows internals. debugging complex issues with Text Input Processors and analyzing Windows security.
        // Reference: https://github.com/taviso/ctftool
        $string1 = /\/ctftool/ nocase ascii wide

    condition:
        any of them
}
