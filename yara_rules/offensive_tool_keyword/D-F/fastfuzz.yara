rule fastfuzz
{
    meta:
        description = "Detection patterns for the tool 'fastfuzz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fastfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast fuzzing websites with chrome extension
        // Reference: https://github.com/tismayil/fastfuz-chrome-ext
        $string1 = /\/fastfuz\-chrome\-ext/ nocase ascii wide
        // Description: Fast fuzzing websites with chrome extension
        // Reference: https://github.com/tismayil/fastfuz-chrome-ext
        $string2 = /fastfuz\-chrome\-ext.{0,1000}files\.txt/ nocase ascii wide

    condition:
        any of them
}
