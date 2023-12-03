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
        $string1 = /.{0,1000}\/autotimeliner.{0,1000}/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string2 = /.{0,1000}\\autotimeline.{0,1000}/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string3 = /.{0,1000}autotimeline\s.{0,1000}/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string4 = /.{0,1000}autotimeline\.py.{0,1000}/ nocase ascii wide
        // Description: Automagically extract forensic timeline from volatile memory dumps.
        // Reference: https://github.com/andreafortuna/autotimeliner
        $string5 = /.{0,1000}autotimeliner\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
