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
        $string1 = /\/HTMLSmuggler\.git/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string2 = /\/HTMLSmuggler\// nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string3 = /\\HTMLSmuggler\\/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string4 = /D00Movenok\/HTMLSmuggler/ nocase ascii wide
        // Description: HTML Smuggling generator&obfuscator for your Red Team operations
        // Reference: https://github.com/D00Movenok/HTMLSmuggler
        $string5 = /HTMLSmuggler\-main/ nocase ascii wide

    condition:
        any of them
}
