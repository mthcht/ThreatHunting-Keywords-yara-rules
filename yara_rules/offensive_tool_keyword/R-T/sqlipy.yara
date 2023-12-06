rule sqlipy
{
    meta:
        description = "Detection patterns for the tool 'sqlipy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlipy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string1 = /\/sqlmap\.zip/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string2 = /codewatchorg\/sqlipy/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string3 = /SQLiPy\.py/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string4 = /sqlmapapi\.py/ nocase ascii wide

    condition:
        any of them
}
