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
        $string1 = /\s\-\-dc\-ip\s.{0,1000}\s\-request\s.{0,1000}\s\-format\shashcat/
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string2 = /\sntlm\.wordlist\s.{0,1000}\-\-hex\-wordlist/
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string3 = "hashcat"
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string4 = /hashcat\-.{0,1000}\.7z/
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string5 = /hashcat\.git/
        // Description: Worlds fastest and most advanced password recovery utility.
        // Reference: https://github.com/hashcat/hashcat
        $string6 = "hashcat/hashcat"

    condition:
        any of them
}
