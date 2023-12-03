rule Nightmangle
{
    meta:
        description = "Detection patterns for the tool 'Nightmangle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nightmangle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string1 = /.{0,1000}\/imperun\s.{0,1000}\s.{0,1000}cmd\.exe\s\/c\swhoami.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string2 = /.{0,1000}\/Nightmangle\.git.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string3 = /.{0,1000}\[\+\]\sBof\sreplay:.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string4 = /.{0,1000}\[\+\]\sSeImpersonatePrivilege\senabled.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string5 = /.{0,1000}1N73LL1G3NC3x\/Nightmangle.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string6 = /.{0,1000}BeaconInjectProcess.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string7 = /.{0,1000}BeaconInjectTemporaryProcess.{0,1000}/ nocase ascii wide
        // Description: ightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent
        // Reference: https://github.com/1N73LL1G3NC3x/Nightmangle
        $string8 = /.{0,1000}Nightmangle\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
