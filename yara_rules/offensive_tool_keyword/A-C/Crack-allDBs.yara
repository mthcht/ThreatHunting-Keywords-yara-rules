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
        $string1 = /.{0,1000}Crack\-allDBs\.git.{0,1000}/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string2 = /.{0,1000}Crack\-allDBs\-main.{0,1000}/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string3 = /.{0,1000}crack\-allDBs\-v1\.py.{0,1000}/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string4 = /.{0,1000}crack\-allDBs\-v2\.py.{0,1000}/ nocase ascii wide
        // Description: bruteforce script for various DB
        // Reference: https://github.com/d3ckx1/Crack-allDBs
        $string5 = /.{0,1000}d3ckx1\/Crack\-allDBs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
