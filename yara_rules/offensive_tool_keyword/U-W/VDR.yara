rule VDR
{
    meta:
        description = "Detection patterns for the tool 'VDR' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VDR"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string1 = /.{0,1000}\srwf\.py\s.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string2 = /.{0,1000}\.\/rwf\.py.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string3 = /.{0,1000}\/VDR\.git.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string4 = /.{0,1000}\/VDR\-main\.zip/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string5 = /.{0,1000}\\VDR\-main\.zip/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string6 = /.{0,1000}EoP\sPoC\sexploiting\sthe\sAMD\sdriver\s.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string7 = /.{0,1000}EoP\sPoC\sexploiting\sthe\sIntel\sdriver\s.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string8 = /.{0,1000}eop_pdfwkrnl\.py.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string9 = /.{0,1000}eop_pdfwkrnl_loop\.py.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string10 = /.{0,1000}eop_rtport\.py.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string11 = /.{0,1000}eop_stdcdrvws64\.py.{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string12 = /.{0,1000}System\stoken\sis\scopied\sto\sthe\scurrent\sprocess\.\sExecuting\scmd\.exe\.\..{0,1000}/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string13 = /.{0,1000}TakahiroHaruyama\/VDR.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
