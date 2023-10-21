rule hashcat
{
    meta:
        description = "Detection patterns for the tool 'hashcat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string1 = /\s\-\-dc\-ip\s.*\s\-request\s.*\s\-format\shashcat/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string2 = /\sntlm\.wordlist\s.*\-\-hex\-wordlist/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string3 = /hashcat/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string4 = /hashcat\-.*\.7z/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string5 = /hashcat\.git/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string6 = /hashcat\/hashcat/ nocase ascii wide

    condition:
        any of them
}