rule combine_harvester
{
    meta:
        description = "Detection patterns for the tool 'combine_harvester' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "combine_harvester"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string1 = /\/combine_harvester\.git/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string2 = /\[X\]\sYour\sharvest\sexploded\:/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string3 = /\\combine\.exe/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string4 = /\\combine_gui\.exe/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string5 = /\\harvest\.cmb/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string6 = /23E06BF12C5BE7641EF89F557C3F6600E1F3881F8DCE7279C2112279E7EC3B988E1A85EC350149007DE78CE5566FCBD18F630D2CDB78C76AA06F2B121F0B3701/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string7 = /combine_harvester\-main/ nocase ascii wide
        // Description: Rust in-memory dumper
        // Reference: https://github.com/m3f157O/combine_harvester
        $string8 = /m3f157O\/combine_harvester/ nocase ascii wide

    condition:
        any of them
}
