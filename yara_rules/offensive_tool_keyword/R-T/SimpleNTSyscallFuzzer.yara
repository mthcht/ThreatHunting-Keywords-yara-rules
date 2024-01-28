rule SimpleNTSyscallFuzzer
{
    meta:
        description = "Detection patterns for the tool 'SimpleNTSyscallFuzzer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleNTSyscallFuzzer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fuzzer for Windows kernel syscalls.
        // Reference: https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $string1 = /\/SimpleNTSyscallFuzzer\.git/ nocase ascii wide
        // Description: Fuzzer for Windows kernel syscalls.
        // Reference: https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $string2 = /FB351327\-0816\-448B\-8FB7\-63B550D6C808/ nocase ascii wide
        // Description: Fuzzer for Windows kernel syscalls.
        // Reference: https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $string3 = /SimpleNtSyscallFuzzer\.v11\.suo/ nocase ascii wide
        // Description: Fuzzer for Windows kernel syscalls.
        // Reference: https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $string4 = /SimpleNTSyscallFuzzer\-main\\/ nocase ascii wide
        // Description: Fuzzer for Windows kernel syscalls.
        // Reference: https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $string5 = /waleedassar\/SimpleNTSyscallFuzzer/ nocase ascii wide

    condition:
        any of them
}
