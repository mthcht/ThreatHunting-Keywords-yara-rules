rule _1_6_C2
{
    meta:
        description = "Detection patterns for the tool '1.6-C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1.6-C2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string1 = /\/1\.6\-C2\.git/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string2 = /\\1\.6\-C2\-main\.zip/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string3 = /\\1_6_C2\.exe/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string4 = /\]\sReceived\sRCON\schallenge\:\s/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string5 = "01a82d6612d5698da1badc96841f2d6835e26ee95af3c536411b6d1b086da811" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string6 = "35d3030e079a68ce10e998b5140d66fbb54b4a6e7f8ed090bf918abc42175dce" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string7 = "c07d3356-7f9b-45e0-a4f7-7b1487d966b8" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string8 = /eversinc33\/1\.6\-C2/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string9 = /getHostnameFromCVARS\(/ nocase ascii wide

    condition:
        any of them
}
