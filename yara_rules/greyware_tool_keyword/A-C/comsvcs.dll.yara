rule comsvcs_dll
{
    meta:
        description = "Detection patterns for the tool 'comsvcs.dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "comsvcs.dll"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Dumping credentials with Minidump ordinal format (suspicious)
        // Reference: N/A
        $string1 = /comsvcs\.dll.{0,1000}\#\+00024764/ nocase ascii wide
        // Description: Dumping credentials with Minidump ordinal format (suspicious)
        // Reference: N/A
        $string2 = /comsvcs\.dll.{0,1000}\#24/ nocase ascii wide
        // Description: Dumping lsass credentials
        // Reference: N/A
        $string3 = /comsvcs\.dll.{0,1000}MiniDump.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}
