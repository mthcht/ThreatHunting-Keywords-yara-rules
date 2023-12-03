rule power_pwn
{
    meta:
        description = "Detection patterns for the tool 'power-pwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "power-pwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string1 = /.{0,1000}\/power\-pwn\.git.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string2 = /.{0,1000}\\malware_runner\.py.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string3 = /.{0,1000}\\power\-pwn\\.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string4 = /.{0,1000}Cleanup\-57BFF48E\-24FB\-48E9\-A390\-AC62ADF38B07\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string5 = /.{0,1000}CodeExec\-D37DA402\-3829\-492F\-90D0\-8EC3909514EB\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string6 = /.{0,1000}Endpoint\-EE15B860\-9EEC\-EC11\-BB3D\-0022482CA4A7\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string7 = /.{0,1000}Exfil\-EC266392\-D6BC\-4F7B\-A4D1\-410166D30B55\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string8 = /.{0,1000}mbrg\/power\-pwn.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string9 = /.{0,1000}powerpwn\.powerdump.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string10 = /.{0,1000}powerpwn_tests.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string11 = /.{0,1000}power\-pwn\-main.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string12 = /.{0,1000}Ransomware\-E20F7CED\-42AD\-485E\-BE4D\-DE21DCE58EC0\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string13 = /.{0,1000}RunCleanup\-77740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string14 = /.{0,1000}RunCodeExec\-75740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string15 = /.{0,1000}RunExfil\-78740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string16 = /.{0,1000}RunRansomware\-76740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string17 = /.{0,1000}RunStealCookie\-8B5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string18 = /.{0,1000}RunStealPowerAutomateToken\-8C5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string19 = /.{0,1000}StealCookie\-28050355\-D9DF\-4CE7\-BFBC\-4F7DDE890C2A\.json.{0,1000}/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string20 = /.{0,1000}StealPowerAutomateToken\-C4E7B7DA\-54E4\-49AB\-B634\-FCCD77C65025\.json.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
