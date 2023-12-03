rule ad_ldap_enum
{
    meta:
        description = "Detection patterns for the tool 'ad-ldap-enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ad-ldap-enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string1 = /.{0,1000}\s\-p\s\'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\'.{0,1000}/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string2 = /.{0,1000}\/ad\-ldap\-enum\.git.{0,1000}/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string3 = /.{0,1000}ad\-ldap\-enum\.py.{0,1000}/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string4 = /.{0,1000}ad\-ldap\-enum\-main.{0,1000}/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string5 = /.{0,1000}CroweCybersecurity\/ad\-ldap\-enum.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
