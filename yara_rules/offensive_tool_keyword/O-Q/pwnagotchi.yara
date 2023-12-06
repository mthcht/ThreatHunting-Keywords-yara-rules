rule pwnagotchi
{
    meta:
        description = "Detection patterns for the tool 'pwnagotchi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnagotchi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pwnagotchi is an A2C-based AI leveraging bettercap that learns from its surrounding WiFi environment to maximize the crackable WPA key material it captures (either passively. or by performing authentication and association attacks). This material is collected as PCAP files containing any form of handshake supported by hashcat. including PMKIDs. full and half WPA handshakes
        // Reference: https://github.com/evilsocket/pwnagotchi
        $string1 = /pwnagotchi/ nocase ascii wide

    condition:
        any of them
}
