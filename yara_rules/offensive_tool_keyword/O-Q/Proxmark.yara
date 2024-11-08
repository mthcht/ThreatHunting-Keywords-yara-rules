rule Proxmark
{
    meta:
        description = "Detection patterns for the tool 'Proxmark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxmark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The proxmark3 is a powerful general purpose RFID tool. the size of a deck of cards. designed to snoop. listen and emulate everything from Low Frequency (125kHz) to High Frequency (13.56MHz) tags.
        // Reference: https://github.com/Proxmark/proxmark3
        $string1 = /\/Proxmark3/ nocase ascii wide

    condition:
        any of them
}
