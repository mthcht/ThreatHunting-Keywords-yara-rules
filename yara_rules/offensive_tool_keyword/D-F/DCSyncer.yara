rule DCSyncer
{
    meta:
        description = "Detection patterns for the tool 'DCSyncer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCSyncer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string1 = /\/DCSyncer\.git/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string2 = "/DCSyncer/releases/download/" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string3 = "/DCSyncer/tarball/" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string4 = "/DCSyncer/zipball/" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string5 = /\\DCSyncer\.sln/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string6 = /\\DCSyncer\-master/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string7 = "253e716a-ab96-4f87-88c7-052231ec2a12" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string8 = "802a7ba4f023cd272eba8de0488848a7667ac0eeb3844108bdca994491846404" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string9 = "b4ce5c82a51a7281bb0d04463c110471ca73f39813ed11c5c51d48d6cf7733e5" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string10 = "c862cc7e0faabfff2c8e8e58cf7fca200ae534aa5f58857331d1377187a19d3a" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string11 = /DCSyncer\.exe/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string12 = /DCSyncer\-master\.zip/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string13 = /DCSyncer\-x64\.exe/ nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string14 = "e94c578a73298e4f6dbb5b3cb4cf4adcea54f6a971e88428f651cd555e5932b0" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string15 = "eb9c1a8804daed7c8ace37adc87ac66b52e7363666e5af7912bb17695df9b4f4" nocase ascii wide
        // Description: Perform DCSync operation
        // Reference: https://github.com/notsoshant/DCSyncer
        $string16 = "notsoshant/DCSyncer" nocase ascii wide

    condition:
        any of them
}
