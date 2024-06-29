rule comsvcs_dll
{
    meta:
        description = "Detection patterns for the tool 'comsvcs.dll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "comsvcs.dll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping credentials via LSASS
        // Reference: N/A
        $string1 = /comsvcs\.dll\,\sMiniDump.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}
