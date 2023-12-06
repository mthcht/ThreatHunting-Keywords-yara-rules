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
        $string1 = /\srwf\.py\s/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string2 = /\.\/rwf\.py/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string3 = /\/VDR\.git/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string4 = /\/VDR\-main\.zip/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string5 = /\\VDR\-main\.zip/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string6 = /EoP\sPoC\sexploiting\sthe\sAMD\sdriver\s/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string7 = /EoP\sPoC\sexploiting\sthe\sIntel\sdriver\s/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string8 = /eop_pdfwkrnl\.py/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string9 = /eop_pdfwkrnl_loop\.py/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string10 = /eop_rtport\.py/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string11 = /eop_stdcdrvws64\.py/ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string12 = /System\stoken\sis\scopied\sto\sthe\scurrent\sprocess\.\sExecuting\scmd\.exe\.\./ nocase ascii wide
        // Description: Vulnerable driver research tool - result and exploit PoCs
        // Reference: https://github.com/TakahiroHaruyama/VDR
        $string13 = /TakahiroHaruyama\/VDR/ nocase ascii wide

    condition:
        any of them
}
