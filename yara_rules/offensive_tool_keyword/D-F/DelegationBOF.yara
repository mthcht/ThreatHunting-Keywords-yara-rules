rule DelegationBOF
{
    meta:
        description = "Detection patterns for the tool 'DelegationBOF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DelegationBOF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1 = /\/DelegationBOF\// nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2 = /\\DelegationBOF\./ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string3 = /DelegationBOF\./ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string4 = /get\-delegation\s.{0,1000}All/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string5 = /get\-delegation\s.{0,1000}Unconstrained/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string6 = /get\-spns\sAll/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string7 = /get\-spns\sASREP/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string8 = /get\-spns\sspns/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string9 = /IcebreakerSecurity\/DelegationBOF/ nocase ascii wide

    condition:
        any of them
}
