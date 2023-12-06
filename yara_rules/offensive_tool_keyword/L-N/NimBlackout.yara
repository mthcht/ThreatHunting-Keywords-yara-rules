rule NimBlackout
{
    meta:
        description = "Detection patterns for the tool 'NimBlackout' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kill AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/Helixo32/NimBlackout
        $string1 = /\/NimBlackout/ nocase ascii wide
        // Description: Kill AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/Helixo32/NimBlackout
        $string2 = /\/NimBlackout/ nocase ascii wide
        // Description: Kill AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/Helixo32/NimBlackout
        $string3 = /\/NimBlackout/ nocase ascii wide
        // Description: Kill AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/Helixo32/NimBlackout
        $string4 = /\/NimBlackout/ nocase ascii wide
        // Description: Kill AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/Helixo32/NimBlackout
        $string5 = /\/NimBlackout/ nocase ascii wide

    condition:
        any of them
}
