rule cerbrutus
{
    meta:
        description = "Detection patterns for the tool 'cerbrutus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cerbrutus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Network brute force tool. written in Python. Faster than other existing solutions (including the main leader in the network brute force market).
        // Reference: https://github.com/Cerbrutus-BruteForcer/cerbrutus
        $string1 = /\/cerbrutus/ nocase ascii wide
        // Description: Network brute force tool. written in Python. Faster than other existing solutions (including the main leader in the network brute force market).
        // Reference: https://github.com/Cerbrutus-BruteForcer/cerbrutus
        $string2 = /cerbrutus\.py/ nocase ascii wide
        // Description: Network brute force tool. written in Python. Faster than other existing solutions (including the main leader in the network brute force market).
        // Reference: https://github.com/Cerbrutus-BruteForcer/cerbrutus
        $string3 = /Cerbrutus\-BruteForcer/ nocase ascii wide
        // Description: Network brute force tool. written in Python. Faster than other existing solutions (including the main leader in the network brute force market).
        // Reference: https://github.com/Cerbrutus-BruteForcer/cerbrutus
        $string4 = /wordlists\/fasttrack\.txt/ nocase ascii wide

    condition:
        any of them
}
