rule supershell
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string1 = /http\:\/\/localhost\:7681/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string2 = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7681\s/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string3 = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7682\s/ nocase ascii wide

    condition:
        any of them
}
