rule CACTUSTORCH
{
    meta:
        description = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CACTUSTORCH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1 = /CACTUSTORCH/ nocase ascii wide

    condition:
        any of them
}
