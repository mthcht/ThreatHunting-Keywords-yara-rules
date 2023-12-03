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
        $string1 = /.{0,1000}\sadhunt\.py\s.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string2 = /.{0,1000}\/ADHunt\.git.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string3 = /.{0,1000}ad_dns_dump\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string4 = /.{0,1000}ADHunt\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string5 = /.{0,1000}dcenum\.run.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string6 = /.{0,1000}delegation_constrained_objects\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string7 = /.{0,1000}delegation_constrained_w_protocol_transition_objects\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string8 = /.{0,1000}delegation_rbcd_objects\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string9 = /.{0,1000}delegation_unconstrained_objects\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string10 = /.{0,1000}karendm\/ADHunt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string11 = /.{0,1000}objects_constrained_delegation_full\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string12 = /.{0,1000}objects_rbcd_delegation_full\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string13 = /.{0,1000}objects_unconstrained_delegation_full\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string14 = /.{0,1000}smbenum\.run.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string15 = /.{0,1000}users_asreproast\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string16 = /.{0,1000}users_dcsrp_full\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string17 = /.{0,1000}users_kerberoasting\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string18 = /.{0,1000}users_no_req_pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string19 = /.{0,1000}users_no_req_pass_full\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string20 = /\/adhunt\.py/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string21 = /\\adhunt\.py/ nocase ascii wide

    condition:
        any of them
}
