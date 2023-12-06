rule Python_Wordlist_Generator
{
    meta:
        description = "Detection patterns for the tool 'Python-Wordlist-Generator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Python-Wordlist-Generator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Create awesome wordlists with Python.
        // Reference: https://github.com/agusmakmun/Python-Wordlist-Generator
        $string1 = /wgen\.py/ nocase ascii wide

    condition:
        any of them
}
