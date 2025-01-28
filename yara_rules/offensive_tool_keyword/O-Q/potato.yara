rule potato
{
    meta:
        description = "Detection patterns for the tool 'potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "potato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string1 = /\\Potato\.exe/ nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string2 = /\\Potato\\obj\\Release\\Potato\.pdb/ nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string3 = /127\.0\.0\.1\/C\$\/Windows\/System32\/utilman\.exe/ nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string4 = "58ba7d7a43c3cbf5ffba7351a6509d04290b41ac5565735c6b6b66ffaf2daaca" nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string5 = "7e21c5b9cf9cb3cc0b3c6909fdf3a7820c6feaa45e86722ed4e7a43d39aee819" nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string6 = "893CC775-335D-4010-9751-D8C8E2A04048" nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string7 = "c391bff39add68d2e9bd97ecfbc98850c2b80f831007df95704eedbc7e93617b" nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string8 = "foxglovesec/Potato" nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string9 = /http\:\/\/127\.0\.0\.1\/wpad\.dat/ nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string10 = /potato\.exe\s\-ip\s/ nocase ascii wide
        // Description: Potato Privilege Escalation on Windows
        // Reference: https://github.com/foxglovesec/Potato
        $string11 = "Starting NBNS spoofer" nocase ascii wide

    condition:
        any of them
}
