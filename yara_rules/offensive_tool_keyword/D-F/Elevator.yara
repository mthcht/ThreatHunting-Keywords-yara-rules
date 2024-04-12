rule Elevator
{
    meta:
        description = "Detection patterns for the tool 'Elevator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Elevator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string1 = /\/Elevator\.git/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string2 = /\[\!\]\sElevated\sprocess\sspawned\!/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string3 = /\\elevator\.exe\s\-/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string4 = /\\Elevator\\target\\release/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string5 = /73415a38d4b76dd2215d9fd81015b36a025018552f7847494f908f50c62fc8d2/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string6 = /AAB75969\-92BA\-4632\-9F78\-AF52FA2BCE1E/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string7 = /elevator\.exe\s.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: UAC bypass by abusing RPC and debug objects.
        // Reference: https://github.com/Kudaes/Elevator
        $string8 = /Kudaes\/Elevator/ nocase ascii wide

    condition:
        any of them
}
