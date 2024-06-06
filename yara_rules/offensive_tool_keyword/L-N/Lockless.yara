rule Lockless
{
    meta:
        description = "Detection patterns for the tool 'Lockless' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lockless"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string1 = /\/LockLess\.exe/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string2 = /\/Lockless\.git/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string3 = /\\LockLess\.csproj/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string4 = /\\LockLess\.exe/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string5 = /\\LockLess\.sln/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string6 = /8c90af89b3f0c90d39396210b6dc8dc19ff9e5ce183463a01affa6d30c5d7414/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string7 = /A91421CB\-7909\-4383\-BA43\-C2992BBBAC22/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string8 = /c591ed58f48171fa285464339a17acd1c267c0299df9f0b4e53eed9a8acb8f9f/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string9 = /f05885a68c1f16c7cbaa3657bbc57f54b7755910d1c96366543cc428729abcb3/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string10 = /GhostPack\/Lockless/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string11 = /LockLess\.exe\s.{0,1000}\/copy/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string12 = /LockLess\.exe\sall/ nocase ascii wide
        // Description: Lockless allows for the copying of locked files.
        // Reference: https://github.com/GhostPack/Lockless
        $string13 = /namespace\sLockLess/ nocase ascii wide

    condition:
        any of them
}
