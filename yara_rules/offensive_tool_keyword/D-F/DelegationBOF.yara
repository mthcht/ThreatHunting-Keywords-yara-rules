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
        $string1 = /.{0,1000}\/DelegationBOF\/.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2 = /.{0,1000}\\DelegationBOF\..{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string3 = /.{0,1000}DelegationBOF\..{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string4 = /.{0,1000}get\-delegation\s.{0,1000}All.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string5 = /.{0,1000}get\-delegation\s.{0,1000}Unconstrained.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string6 = /.{0,1000}get\-spns\sAll.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string7 = /.{0,1000}get\-spns\sASREP.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string8 = /.{0,1000}get\-spns\sspns.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string9 = /.{0,1000}IcebreakerSecurity\/DelegationBOF.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings. Currently. it supports RBCD. Constrained. Constrained w/Protocol Transition. and Unconstrained Delegation checks.
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string10 = /get\-delegation\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
