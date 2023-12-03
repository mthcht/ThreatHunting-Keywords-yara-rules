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
        $string1 = /.{0,1000}\/sqlmap\.zip.{0,1000}/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string2 = /.{0,1000}codewatchorg\/sqlipy.{0,1000}/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string3 = /.{0,1000}SQLiPy\.py.{0,1000}/ nocase ascii wide
        // Description: SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
        // Reference: https://github.com/codewatchorg/sqlipy
        $string4 = /.{0,1000}sqlmapapi\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
