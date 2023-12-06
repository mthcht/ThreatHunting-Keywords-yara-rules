rule SharpKiller
{
    meta:
        description = "Detection patterns for the tool 'SharpKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string1 = /\/SharpKiller\.git/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string2 = /\/Sharp\-Killer\.sln/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string3 = /\\AMSIPatcher\.cs/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string4 = /\\Sharp\-Killer\.sln/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string5 = /4DD3206C\-F14A\-43A3\-8EA8\-88676810B8CD/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string6 = /S1lkys\/SharpKiller/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string7 = /Sharp\-Killer\.csproj/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string8 = /Sharp\-Killer\.exe/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string9 = /Sharp\-Killer\.pdb/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string10 = /SharpKiller\-main/ nocase ascii wide

    condition:
        any of them
}
