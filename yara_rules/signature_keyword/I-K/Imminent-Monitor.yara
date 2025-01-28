rule Imminent_Monitor
{
    meta:
        description = "Detection patterns for the tool 'Imminent-Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imminent-Monitor"
        rule_category = "signature_keyword"

    strings:
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string1 = /Win\.Packed\.Immirat\-/ nocase ascii wide

    condition:
        any of them
}
