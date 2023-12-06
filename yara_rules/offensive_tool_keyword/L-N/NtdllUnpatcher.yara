rule NtdllUnpatcher
{
    meta:
        description = "Detection patterns for the tool 'NtdllUnpatcher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtdllUnpatcher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string1 = /\/NtdllUnpatcher\.git/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string2 = /NtdllUnpatcher\.cpp/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string3 = /NtdllUnpatcher\.dll/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string4 = /NtdllUnpatcher\.lib/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string5 = /NtdllUnpatcher\.log/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string6 = /NtdllUnpatcher\.obj/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string7 = /NtdllUnpatcher\.sln/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string8 = /NtdllUnpatcher_Injector/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string9 = /NtdllUnpatcher\-master/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string10 = /Signal\-Labs\/NtdllUnpatcher/ nocase ascii wide

    condition:
        any of them
}
