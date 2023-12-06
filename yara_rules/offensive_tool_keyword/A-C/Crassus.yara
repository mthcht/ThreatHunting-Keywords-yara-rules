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
        $string1 = /\/Crassus\.git/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string2 = /\/Crassus\-main/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string3 = /\\Crassus\-main/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string4 = /7E9729AA\-4CF2\-4D0A\-8183\-7FB7CE7A5B1A/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string5 = /Crassus\.csproj/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string6 = /Crassus\.exe/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string7 = /Crassus\.sln/ nocase ascii wide
        // Description: Crassus Windows privilege escalation discovery tool
        // Reference: https://github.com/vu-ls/Crassus
        $string8 = /vu\-ls\/Crassus/ nocase ascii wide

    condition:
        any of them
}
