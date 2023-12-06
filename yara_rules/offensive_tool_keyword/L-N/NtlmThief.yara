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
        $string3 = /CD517B47\-6CA1\-4AC3\-BC37\-D8A27F2F03A0/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string4 = /MzHmO\/NtlmThief/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string5 = /NtlmThief\.exe/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string6 = /NtlmThief\.sln/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string7 = /NtlmThief\.vcxproj/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string8 = /NtlmThief\-main/ nocase ascii wide

    condition:
        any of them
}
