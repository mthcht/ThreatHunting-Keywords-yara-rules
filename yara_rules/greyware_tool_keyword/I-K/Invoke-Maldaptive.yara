rule Invoke_Maldaptive
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Maldaptive' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Maldaptive"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string1 = /\/Invoke\-Maldaptive\.git/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string2 = /\\Invoke\-Maldaptive\-main/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string3 = /\\Obfuscated_Command\.txt/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string4 = /275de3390b20723991268204fb3f70b0ec76dba29f809ac0152588cecc22e87f/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string5 = /50c178847f0454a84f85bc765699c1180ea1b49f91e7d70b5b9113845d008387/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string6 = /7215255a842142ffa7f7e1624942684279e9a2f14fa7947451a3194d0b608f52/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string7 = /db015ab1\-abcd\-1234\-5678\-133337c0ffee/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string8 = /Disable\-LdapClientWinEvent\s\-ProcessName\s/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string9 = /e8f71ea9428bb466651b9cd3a2ed3a726d1a07712bd611330def1ebfcbc68b47/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string10 = /https\:\/\/github\.com\/mandiant\/SilkETW\/releases\/download\/v0\.8\/SilkETW_SilkService_v8\.zip/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string11 = /Invoke\-LdapBranchVisitor/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string12 = /Invoke\-LdapQuery\s\-.{0,1000}ConvertFrom\-LdapSearchResult/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string13 = /Invoke\-Maldaptive/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string14 = /MaLDAPtive\sis\sa\sframework\sfor\sLDAP\sSearchFilter\sparsing\,\sobfuscation\,\sdeobfuscation\sand\sdetection/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string15 = /Maldaptive\.pd1/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string16 = /Maldaptive\.psm1/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string17 = /MaLDAPtive\/Invoke\-Maldaptive/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string18 = /New\-ObfuscationContainer\s\-SearchFilter\s\$SearchFilter\s\-SearchRoot\:\$SearchRoot\s\-AttributeList/ nocase ascii wide
        // Description: MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // Reference: https://github.com/MaLDAPtive/Invoke-Maldaptive
        $string19 = /serviceName\s\=\s\'SilkService/ nocase ascii wide

    condition:
        any of them
}
