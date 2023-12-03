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
        $string1 = /.{0,1000}\/NtdllUnpatcher\.git.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string2 = /.{0,1000}NtdllUnpatcher\.cpp.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string3 = /.{0,1000}NtdllUnpatcher\.dll.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string4 = /.{0,1000}NtdllUnpatcher\.lib.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string5 = /.{0,1000}NtdllUnpatcher\.log.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string6 = /.{0,1000}NtdllUnpatcher\.obj.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string7 = /.{0,1000}NtdllUnpatcher\.sln.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string8 = /.{0,1000}NtdllUnpatcher_Injector.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string9 = /.{0,1000}NtdllUnpatcher\-master.{0,1000}/ nocase ascii wide
        // Description: code for EDR bypassing
        // Reference: https://github.com/Signal-Labs/NtdllUnpatcher
        $string10 = /.{0,1000}Signal\-Labs\/NtdllUnpatcher.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
