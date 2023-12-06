rule RainbowCrack
{
    meta:
        description = "Detection patterns for the tool 'RainbowCrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RainbowCrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The RainbowCrack tool is a hash cracker that makes use of a large-scale time-memory trade-off. A traditional brute force cracker tries all possible plaintexts one by one. which can be time consuming for complex passwords. RainbowCrack uses a time-memory trade-off to do all the cracking-time computation in advance and store the results in so-called rainbow tables. It does take a long time to precompute the tables but RainbowCrack can be hundreds of times faster than a brute force cracker once the precomputation is finished. For downloads and more information. visit the RainbowCrack homepage
        // Reference: http://project-rainbowcrack.com/
        $string1 = /RainbowCrack/ nocase ascii wide

    condition:
        any of them
}
