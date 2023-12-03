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
        $string1 = /.{0,1000}\/NtlmThief\.git.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string2 = /.{0,1000}\\NtlmThief\\.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string3 = /.{0,1000}CD517B47\-6CA1\-4AC3\-BC37\-D8A27F2F03A0.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string4 = /.{0,1000}MzHmO\/NtlmThief.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string5 = /.{0,1000}NtlmThief\.exe.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string6 = /.{0,1000}NtlmThief\.sln.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string7 = /.{0,1000}NtlmThief\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string8 = /.{0,1000}NtlmThief\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
