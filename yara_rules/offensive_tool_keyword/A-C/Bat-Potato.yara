rule Bat_Potato
{
    meta:
        description = "Detection patterns for the tool 'Bat-Potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bat-Potato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string1 = /\sBat\-Potato\.bat/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string2 = /\/Bat\-Potato\.bat/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string3 = /\/Bat\-Potato\.git/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string4 = /\\Juicy\-Potato\-x86\-master/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string5 = "0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string6 = "0x4xel/Bat-Potato" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string7 = "74e35d9c8f14042101ba70a5754c800de149c83d5ddfd2303f99fff92f7b4d7c" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string8 = "878273cce2ef59c3bf4a3e4533a6b4101c9a21d57cc629cabe12ef6a05c8dda9" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string9 = /Bat\-Potato\-main\.zip/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string10 = "e8d4f270bb109e0a3930dc3bf3413d8d071d283c19054809057fb9560f4daa44" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string11 = "e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db" nocase ascii wide

    condition:
        any of them
}
