rule fuzz_txt
{
    meta:
        description = "Detection patterns for the tool 'fuzz.txt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuzz.txt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: list of sensible files for fuzzing in system
        // Reference: https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt
        $string1 = /\/fuzz\.txt/ nocase ascii wide

    condition:
        any of them
}
