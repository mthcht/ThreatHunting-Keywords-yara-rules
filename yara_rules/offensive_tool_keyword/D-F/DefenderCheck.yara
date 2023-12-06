rule DefenderCheck
{
    meta:
        description = "Detection patterns for the tool 'DefenderCheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefenderCheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quick tool to help make evasion work a little bit easier.Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on. and then prints those offending bytes to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.
        // Reference: https://github.com/matterpreter/DefenderCheck
        $string1 = /DefenderCheck/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string2 = /DefenderCheck\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string3 = /matterpreter\/DefenderCheck/ nocase ascii wide

    condition:
        any of them
}
