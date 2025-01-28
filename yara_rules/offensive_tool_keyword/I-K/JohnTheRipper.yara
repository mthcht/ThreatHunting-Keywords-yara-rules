rule JohnTheRipper
{
    meta:
        description = "Detection patterns for the tool 'JohnTheRipper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JohnTheRipper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string1 = /\s\-\-format\=NT\s\-w\=.{0,1000}_password\.txt/
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string2 = /john\s.{0,1000}\s\-\-wordlist\=/
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string3 = /john\sNTDS\.dit/
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string4 = /John.{0,1000}the.{0,1000}Ripper/

    condition:
        any of them
}
