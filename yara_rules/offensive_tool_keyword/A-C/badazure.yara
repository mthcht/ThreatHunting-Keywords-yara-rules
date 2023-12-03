rule badazure
{
    meta:
        description = "Detection patterns for the tool 'badazure' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badazure"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string1 = /.{0,1000}\s\-Build\s\-NoAttackPaths.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string2 = /.{0,1000}\/BadZure\.git.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string3 = /.{0,1000}\/BadZure\/.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string4 = /.{0,1000}\\BadZure.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string5 = /.{0,1000}BadZure\-main.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string6 = /.{0,1000}\-Build\s\$RandomAttackPath.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string7 = /.{0,1000}Invoke\-BadZure.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string8 = /.{0,1000}mvelazc0\/BadZure.{0,1000}/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string9 = /.{0,1000}\-RandomAttackPath\s\-Token.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
