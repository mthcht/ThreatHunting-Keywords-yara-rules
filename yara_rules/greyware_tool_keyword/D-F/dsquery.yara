rule dsquery
{
    meta:
        description = "Detection patterns for the tool 'dsquery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsquery"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with dsquery
        // Reference: N/A
        $string1 = /dsquery\s.*\s\-filter\s.*\(objectClass\=trustedDomain\).*\s\-attr\s/ nocase ascii wide
        // Description: Finding users Not Required to Have a Password
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string2 = /\-filter\s.*\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=32/ nocase ascii wide
        // Description: Finding accounts with Kerberos Pre-Authentication Disabled
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string3 = /\-filter\s.*\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=4194304/ nocase ascii wide
        // Description: Finding accounts with constrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string4 = /\-filter\s.*\(\&\(objectClass\=User\)\(msDS\-AllowedToDelegateTo\=/ nocase ascii wide
        // Description: Finding Kerberoastable Users
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string5 = /\-filter\s.*\(\&\(objectClass\=user\)\(servicePrincipalName\=.*\)\(\!\(cn\=krbtgt\)\)\(\!\(samaccounttype\=805306369/ nocase ascii wide
        // Description: Finding accounts with SPNs
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string6 = /\-filter\s.*\(\&\(objectClass\=User\)\(serviceprincipalname\=.*\)\(samaccountname\=.*\s\-limit\s0\s\-attr\ssamaccountname\sserviceprincipalname/ nocase ascii wide
        // Description: Finding accounts with unconstrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string7 = /\-filter\s.*\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=524288\)/ nocase ascii wide

    condition:
        any of them
}