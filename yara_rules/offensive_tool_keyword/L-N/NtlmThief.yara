rule NtlmThief
{
    meta:
        description = "Detection patterns for the tool 'NtlmThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string1 = /\/NtlmThief\.git/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string2 = /\\NtlmThief\\/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string3 = "12d55d1fbe1ca3c7889434234adfda1abfbd5a8aacb076026b4a94e81d696bd5" nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string4 = "230184a9e6df447df04c22c92e6cb0d494d210fb6ec4b3350d16712d1e85d6b9" nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string5 = "4ce98911b8e13393c58578be23e85776dbf7c95ec878b9f08748d0921855c36b" nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string6 = "CD517B47-6CA1-4AC3-BC37-D8A27F2F03A0" nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string7 = "MzHmO/NtlmThief" nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string8 = /NtlmThief\.exe/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string9 = /NtlmThief\.sln/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string10 = /NtlmThief\.vcxproj/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string11 = "NtlmThief-main" nocase ascii wide

    condition:
        any of them
}
