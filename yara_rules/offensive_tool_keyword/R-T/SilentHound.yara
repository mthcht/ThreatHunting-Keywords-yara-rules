rule SilentHound
{
    meta:
        description = "Detection patterns for the tool 'SilentHound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string1 = /\s\-k\s\-\-kerberoast/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string2 = /\/SilentHound\.git/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string3 = /\-domain_admins\.txt/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string4 = /layer8secure\/SilentHound/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string5 = /Nick\sSwink\saka\sc0rnbread/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string6 = /silenthound\.py/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string7 = /SilentHound\-main/ nocase ascii wide

    condition:
        any of them
}
