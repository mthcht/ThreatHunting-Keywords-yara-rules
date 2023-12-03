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
        $string1 = /.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-request\s.{0,1000}\s\-format\shashcat.{0,1000}/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string2 = /.{0,1000}\sntlm\.wordlist\s.{0,1000}\-\-hex\-wordlist.{0,1000}/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string3 = /.{0,1000}hashcat.{0,1000}/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string4 = /.{0,1000}hashcat\-.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string5 = /.{0,1000}hashcat\.git.{0,1000}/ nocase ascii wide
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string6 = /.{0,1000}hashcat\/hashcat.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
