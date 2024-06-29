rule SafetyDump
{
    meta:
        description = "Detection patterns for the tool 'SafetyDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string1 = /\/SafetyDump\.exe/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string2 = /\/SafetyDump\.git/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string3 = /\\SafetyDump\.csproj/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string4 = /\\SafetyDump\.exe/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string5 = /\\SafetyDump\.sln/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string6 = /738f3dce5ad63a16b2cf8b236d8d374022f121c0990e92adc214a6d03b0dc345/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string7 = /8347E81B\-89FC\-42A9\-B22C\-F59A6A572DEC/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string8 = /88888dcb2ac77d09b3c68c26f025f1e1ba9db667f3950a79a110896de297e162/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string9 = /989cb6a23ecba5fb7785a1e23b61b84c12ff45723eb98bb885905768e0a9550a/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string10 = /namespace\sSafetyDump/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string11 = /riskydissonance\/SafetyDump/ nocase ascii wide
        // Description: uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output. This allows the dump to be redirected to a file or straight back down C2 or through other tools
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string12 = /SafetyDump\.exe\s/ nocase ascii wide

    condition:
        any of them
}
