rule pastehakk
{
    meta:
        description = "Detection patterns for the tool 'pastehakk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastehakk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string1 = /\spastehakk\.sh/
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string2 = /\$\{White\}A\stool\sto\sperform\sclipboard\spoisoning\sattack/
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string3 = /\$Green\sInfecting\shtml\sfile/
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string4 = /\/pastehakk\.git/ nocase ascii wide
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string5 = /\/pastehakk\.sh/
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string6 = "3xploitGuy/pastehakk" nocase ascii wide
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string7 = "53a9c6eed3ee5ed0ea6fe900bbcdac2b9c0709c57c8d82688ef32f7e2b784f60"
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string8 = "clear; history -c"
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string9 = "pastehakk_generate"
        // Description: perform clipboard poisoning or paste jacking attack
        // Reference: https://github.com/3xploitGuy/pastehakk
        $string10 = /sandeshyadavm46\@gmail\.com/

    condition:
        any of them
}
