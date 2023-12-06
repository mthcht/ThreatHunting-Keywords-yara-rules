rule usbpcap
{
    meta:
        description = "Detection patterns for the tool 'usbpcap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "usbpcap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: USB capture for Windows.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string1 = /USBPcap/ nocase ascii wide

    condition:
        any of them
}
