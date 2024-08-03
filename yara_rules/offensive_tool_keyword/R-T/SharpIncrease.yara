rule SharpIncrease
{
    meta:
        description = "Detection patterns for the tool 'SharpIncrease' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpIncrease"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string1 = /\/SharpIncrease\.exe/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string2 = /\/SharpIncrease\.git/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string3 = /\\SharpIncrease\.exe/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string4 = /\\SharpIncrease\.sln/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string5 = /\>SharpIncrease\</ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string6 = /77849d97ebdb4c100d7195a3904fb6b829219bb9f8df46dd81151550546da532/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string7 = /84075d23f3358b16e1f68b1eb56d34d34e88da9b29d504d36b5de2522cf6c23f/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string8 = /B19E7FDE\-C2CB\-4C0A\-9C5E\-DFC73ADDB5C0/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string9 = /f36ae1ef8fa544943bbd65f44d53fd994b42c91042e133c69019c66e73b20278/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string10 = /mertdas\/SharpIncrease/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string11 = /SharpIncrease\.exe\s\-D\s/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string12 = /SharpIncrease\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
