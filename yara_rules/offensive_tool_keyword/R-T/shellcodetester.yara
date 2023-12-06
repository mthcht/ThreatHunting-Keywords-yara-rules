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
        $string1 = /\/shellcodetester/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string2 = /shellcodetester\s/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string3 = /ShellCodeTester\.csproj/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string4 = /shellcodetester\.exe/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string5 = /shellcodetester\.git/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string6 = /shellcodetester\.sh/ nocase ascii wide
        // Description: This tools test generated ShellCodes
        // Reference: https://github.com/helviojunior/shellcodetester
        $string7 = /ShellCodeTester\.sln/ nocase ascii wide

    condition:
        any of them
}
