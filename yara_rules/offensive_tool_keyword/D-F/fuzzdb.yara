rule fuzzdb
{
    meta:
        description = "Detection patterns for the tool 'fuzzdb' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuzzdb"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing. Its the first and most comprehensive open dictionary of fault injection patterns. predictable resource locations. and regex for matching server responses.
        // Reference: https://github.com/fuzzdb-project/fuzzdb
        $string1 = /fuzzdb/ nocase ascii wide

    condition:
        any of them
}
