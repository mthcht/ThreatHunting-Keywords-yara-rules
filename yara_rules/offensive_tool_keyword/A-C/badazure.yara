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
        $string1 = /\s\-Build\s\-NoAttackPaths/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string2 = /\/BadZure\.git/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string3 = /\/BadZure\// nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string4 = /\\BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string5 = /BadZure\-main/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string6 = /\-Build\s\$RandomAttackPath/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string7 = /Invoke\-BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string8 = /mvelazc0\/BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string9 = /\-RandomAttackPath\s\-Token/ nocase ascii wide

    condition:
        any of them
}
