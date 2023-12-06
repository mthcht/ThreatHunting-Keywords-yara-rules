rule firesheep
{
    meta:
        description = "Detection patterns for the tool 'firesheep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "firesheep"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Free program for HTTP session hijacking attacks.
        // Reference: https://codebutler.github.io/firesheep/
        $string1 = /Firesheep\// nocase ascii wide

    condition:
        any of them
}
