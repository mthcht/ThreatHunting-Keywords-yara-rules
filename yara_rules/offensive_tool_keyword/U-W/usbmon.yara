rule usbmon
{
    meta:
        description = "Detection patterns for the tool 'usbmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "usbmon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: USB capture for Linux.
        // Reference: https://www.kernel.org/doc/Documentation/usb/usbmon.txt
        $string1 = /\\usbmon\.txt/ nocase ascii wide

    condition:
        any of them
}
