rule DumpNParse
{
    meta:
        description = "Detection patterns for the tool 'DumpNParse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpNParse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string1 = /\/DumpNParse\.exe/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string2 = /\/DumpNParse\.git/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string3 = /\\\\windows\\\\temp\\\\lsass\.dmp/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string4 = /\\DumpNParse\.exe/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string5 = /\\DumpNParse\-main/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string6 = "BA1F3992-9654-4424-A0CC-26158FDFBF74" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string7 = /C\:\\Users\\.{0,1000}\\lsass_.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string8 = /DumpNParse\-main\.zip/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string9 = "f038fdbc3ed50ebbf1ebc1c814836bcf93b4c149e5856ccf9b5400da8a974117" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string10 = "icyguider/DumpNParse" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string11 = "lsass dump saved to: " nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string12 = /Program\.MiniDump\sminidump/ nocase ascii wide

    condition:
        any of them
}
