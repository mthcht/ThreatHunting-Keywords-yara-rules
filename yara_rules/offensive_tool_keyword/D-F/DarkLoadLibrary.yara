rule DarkLoadLibrary
{
    meta:
        description = "Detection patterns for the tool 'DarkLoadLibrary' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkLoadLibrary"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LoadLibrary for offensive operations
        // Reference: https://github.com/bats3c/DarkLoadLibrary
        $string1 = /.{0,1000}\/DarkLoadLibrary\.git.{0,1000}/ nocase ascii wide
        // Description: LoadLibrary for offensive operations
        // Reference: https://github.com/bats3c/DarkLoadLibrary
        $string2 = /.{0,1000}\\DarkLoadLibrary\..{0,1000}/ nocase ascii wide
        // Description: LoadLibrary for offensive operations
        // Reference: https://github.com/bats3c/DarkLoadLibrary
        $string3 = /.{0,1000}bats3c\/DarkLoadLibrary.{0,1000}/ nocase ascii wide
        // Description: LoadLibrary for offensive operations
        // Reference: https://github.com/bats3c/DarkLoadLibrary
        $string4 = /.{0,1000}DarkLoadLibrary\-maser.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
