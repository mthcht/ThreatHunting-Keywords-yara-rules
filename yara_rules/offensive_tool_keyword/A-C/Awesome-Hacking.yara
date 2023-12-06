rule Awesome_Hacking
{
    meta:
        description = "Detection patterns for the tool 'Awesome-Hacking' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Awesome-Hacking"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of awesome lists for hackers. pentesters & security researchers.
        // Reference: https://github.com/Hack-with-Github/Awesome-Hacking
        $string1 = /Awesome\-Hacking/ nocase ascii wide

    condition:
        any of them
}
