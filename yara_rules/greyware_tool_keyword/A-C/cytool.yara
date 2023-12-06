rule cytool
{
    meta:
        description = "Detection patterns for the tool 'cytool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cytool"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Disables event collection
        // Reference: N/A
        $string1 = /cytool\.exe\sevent_collection\sdisable/ nocase ascii wide
        // Description: Disables protection on Cortex XDR files processes registry and services
        // Reference: N/A
        $string2 = /cytool\.exe\sprotect\sdisable/ nocase ascii wide
        // Description: Disables Cortex XDR (Even with tamper protection enabled)
        // Reference: N/A
        $string3 = /cytool\.exe\sruntime\sdisable/ nocase ascii wide
        // Description: Disables the cortex agent on startup
        // Reference: N/A
        $string4 = /cytool\.exe\sstartup\sdisable/ nocase ascii wide

    condition:
        any of them
}
