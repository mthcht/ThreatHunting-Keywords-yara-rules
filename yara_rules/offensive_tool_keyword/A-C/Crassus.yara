rule Crassus
{
    meta:
        description = "Detection patterns for the tool 'Crassus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crassus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string1 = /.{0,1000}\/Crassus\.git.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string2 = /.{0,1000}\/Crassus\-main.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string3 = /.{0,1000}\\Crassus\-main.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string4 = /.{0,1000}7E9729AA\-4CF2\-4D0A\-8183\-7FB7CE7A5B1A.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string5 = /.{0,1000}Crassus\.csproj.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string6 = /.{0,1000}Crassus\.exe.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string7 = /.{0,1000}Crassus\.sln.{0,1000}/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string8 = /.{0,1000}vu\-ls\/Crassus.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
