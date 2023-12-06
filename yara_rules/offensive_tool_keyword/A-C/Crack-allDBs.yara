rule Crack_allDBs
{
    meta:
        description = "Detection patterns for the tool 'Crack-allDBs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crack-allDBs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string1 = /Crack\-allDBs\.git/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string2 = /Crack\-allDBs\-main/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string3 = /crack\-allDBs\-v1\.py/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string4 = /crack\-allDBs\-v2\.py/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string5 = /d3ckx1\/Crack\-allDBs/ nocase ascii wide

    condition:
        any of them
}
