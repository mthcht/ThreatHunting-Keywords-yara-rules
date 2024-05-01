rule prefetch_tool
{
    meta:
        description = "Detection patterns for the tool 'prefetch-tool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prefetch-tool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string1 = /\/prefetch\-tool\.git/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string2 = /\\prefetch_leak\.h/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string3 = /\\prefetch_tool\.sln/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string4 = /\\prefetch_tool\.vcxproj/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string5 = /82ac960f25131540ae230b2bac0f003ffc8edc8a05382d8831ff8e8ebf30996d/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string6 = /8aba74be7acef3c84cef0163411298aa994872347a4ac84cc0a0d19ddf0eb65c/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string7 = /A46C9A13\-145E\-42C0\-8CA6\-CC920BF1D9F1/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string8 = /exploits\-forsale\/prefetch\-tool/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string9 = /include\s\"prefetch_leak\.h\"/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string10 = /lallousz\-x86\@yahoo\.com/ nocase ascii wide

    condition:
        any of them
}
