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
        $string1 = /.{0,1000}\/SharpKiller\.git.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string2 = /.{0,1000}\/Sharp\-Killer\.sln.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string3 = /.{0,1000}\\AMSIPatcher\.cs.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string4 = /.{0,1000}\\Sharp\-Killer\.sln.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string5 = /.{0,1000}4DD3206C\-F14A\-43A3\-8EA8\-88676810B8CD.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string6 = /.{0,1000}S1lkys\/SharpKiller.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string7 = /.{0,1000}Sharp\-Killer\.csproj.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string8 = /.{0,1000}Sharp\-Killer\.exe.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string9 = /.{0,1000}Sharp\-Killer\.pdb.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // Reference: https://github.com/S1lkys/SharpKiller
        $string10 = /.{0,1000}SharpKiller\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
