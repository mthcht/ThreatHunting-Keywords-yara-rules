rule Invoke_PowerIncrease
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PowerIncrease' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PowerIncrease"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/The-Viper-One/Invoke-PowerIncrease
        $string1 = "42e42476084102789dfef4a1369a3028c2319de6a34ba704db907dedf63e2b29" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/The-Viper-One/Invoke-PowerIncrease
        $string2 = "Invoke-PowerIncrease -SourceFilePath " nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/The-Viper-One/Invoke-PowerIncrease
        $string3 = /Invoke\-PowerIncrease\.ps1/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/The-Viper-One/Invoke-PowerIncrease
        $string4 = "The-Viper-One/Invoke-PowerIncrease" nocase ascii wide

    condition:
        any of them
}
