rule DueDLLigence
{
    meta:
        description = "Detection patterns for the tool 'DueDLLigence' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DueDLLigence"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string1 = /\/DueDLLigence\.git/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string2 = /\\duedlligence\.dll/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string3 = /73948912\-CEBD\-48ED\-85E2\-85FCD1D4F560/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string4 = /DueDLLigence\.cs/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string5 = /DueDLLigence\.sln/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string6 = /DueDLLigence\-master/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string7 = /mandiant\/DueDLLigence/ nocase ascii wide

    condition:
        any of them
}
