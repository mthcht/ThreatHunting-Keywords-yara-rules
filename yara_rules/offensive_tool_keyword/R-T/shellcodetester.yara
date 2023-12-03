rule shellcodetester
{
    meta:
        description = "Detection patterns for the tool 'shellcodetester' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shellcodetester"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string1 = /.{0,1000}\/shellcodetester.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string2 = /.{0,1000}shellcodetester\s.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string3 = /.{0,1000}ShellCodeTester\.csproj.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string4 = /.{0,1000}shellcodetester\.exe.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string5 = /.{0,1000}shellcodetester\.git.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string6 = /.{0,1000}shellcodetester\.sh.{0,1000}/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string7 = /.{0,1000}ShellCodeTester\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
