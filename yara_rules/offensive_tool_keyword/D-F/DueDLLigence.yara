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
        $string1 = /.{0,1000}\/DueDLLigence\.git.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string2 = /.{0,1000}\\duedlligence\.dll.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string3 = /.{0,1000}73948912\-CEBD\-48ED\-85E2\-85FCD1D4F560.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string4 = /.{0,1000}DueDLLigence\.cs.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string5 = /.{0,1000}DueDLLigence\.sln.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string6 = /.{0,1000}DueDLLigence\-master.{0,1000}/ nocase ascii wide
        // Description: Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // Reference: https://github.com/mandiant/DueDLLigence
        $string7 = /.{0,1000}mandiant\/DueDLLigence.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
