rule ADExplorerSnapshot_py
{
    meta:
        description = "Detection patterns for the tool 'ADExplorerSnapshot.py' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADExplorerSnapshot.py"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ADExplorerSnapshot.py is an AD Explorer snapshot parser. It is made as an ingestor for BloodHound and also supports full-object dumping to NDJSON.
        // Reference: https://github.com/c3c/ADExplorerSnapshot.py
        $string1 = /.{0,1000}ADExplorerSnapshot\.py.{0,1000}/ nocase ascii wide
        // Description: ADExplorerSnapshot.py is an AD Explorer snapshot parser. It is made as an ingestor for BloodHound and also supports full-object dumping to NDJSON.
        // Reference: https://github.com/c3c/ADExplorerSnapshot.py
        $string2 = /.{0,1000}ADExplorerSnapshot\.py\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
