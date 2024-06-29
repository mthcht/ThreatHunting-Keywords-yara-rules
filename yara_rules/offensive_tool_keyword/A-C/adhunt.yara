rule adhunt
{
    meta:
        description = "Detection patterns for the tool 'adhunt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adhunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string1 = /\sadhunt\.py\s/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string2 = /\/ADHunt\.git/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string3 = /\/adhunt\.py/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string4 = /ad_dns_dump\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string5 = /ADHunt\-main\.zip/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string6 = /dcenum\.run/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string7 = /delegation_constrained_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string8 = /delegation_constrained_w_protocol_transition_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string9 = /delegation_rbcd_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string10 = /delegation_unconstrained_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string11 = /karendm\/ADHunt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string12 = /objects_constrained_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string13 = /objects_rbcd_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string14 = /objects_unconstrained_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string15 = /smbenum\.run/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string16 = /users_asreproast\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string17 = /users_dcsrp_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string18 = /users_kerberoasting\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string19 = /users_no_req_pass\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string20 = /users_no_req_pass_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string21 = /\\adhunt\.py/ nocase ascii wide

    condition:
        any of them
}
