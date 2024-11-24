rule _base64
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AMSI Bypass AmsiScanBuffer in base64
        // Reference: N/A
        $string1 = "QW1zaVNjYW5CdWZmZXI=" nocase ascii wide
        // Description: start of an executable payload in base64
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string2 = "TVqQAAMAAAAEAAAA" nocase ascii wide

    condition:
        any of them
}
