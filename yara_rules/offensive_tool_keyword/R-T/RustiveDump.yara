rule RustiveDump
{
    meta:
        description = "Detection patterns for the tool 'RustiveDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustiveDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string1 = /\/RustiveDump\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string2 = /\/RustiveDump\.git/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string3 = /\[\+\]\sDump\ssent\ssuccessfully\sto\sremote\shost\!/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string4 = /\\rustive\.dmp/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string5 = /\\RustiveDump\.bin/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string6 = /\\RustiveDump\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using only NTAPIs
        // Reference: https://github.com/safedv/RustiveDump
        $string7 = "safedv/RustiveDump" nocase ascii wide

    condition:
        any of them
}
