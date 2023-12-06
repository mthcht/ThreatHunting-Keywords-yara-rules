rule autotimeliner
{
    meta:
        description = "Detection patterns for the tool 'autotimeliner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autotimeliner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string1 = /\/autotimeliner/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string2 = /\\autotimeline/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string3 = /autotimeline\s/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string4 = /autotimeline\.py/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string5 = /autotimeliner\.git/ nocase ascii wide

    condition:
        any of them
}
