rule goPassGen
{
    meta:
        description = "Detection patterns for the tool 'goPassGen' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goPassGen"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Easily-guessable Password Generator for Password Spray Attack
        // Reference: https://github.com/bigb0sss/goPassGen
        $string1 = /.{0,1000}\/goPassGen\.git.{0,1000}/ nocase ascii wide
        // Description: Easily-guessable Password Generator for Password Spray Attack
        // Reference: https://github.com/bigb0sss/goPassGen
        $string2 = /.{0,1000}bigb0sss\/goPassGen.{0,1000}/ nocase ascii wide
        // Description: Easily-guessable Password Generator for Password Spray Attack
        // Reference: https://github.com/bigb0sss/goPassGen
        $string3 = /.{0,1000}goPassGen\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
