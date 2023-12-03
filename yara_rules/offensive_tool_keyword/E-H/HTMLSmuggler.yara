rule HTMLSmuggler
{
    meta:
        description = "Detection patterns for the tool 'HTMLSmuggler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HTMLSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string1 = /.{0,1000}\/HTMLSmuggler\.git.{0,1000}/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string2 = /.{0,1000}\/HTMLSmuggler\/.{0,1000}/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string3 = /.{0,1000}\\HTMLSmuggler\\.{0,1000}/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string4 = /.{0,1000}D00Movenok\/HTMLSmuggler.{0,1000}/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string5 = /.{0,1000}HTMLSmuggler\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
