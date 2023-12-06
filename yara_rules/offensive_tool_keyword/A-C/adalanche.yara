rule adalanche
{
    meta:
        description = "Detection patterns for the tool 'adalanche' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adalanche"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string1 = /\s\-\-authmode\sntlm\s\-\-username\s.{0,1000}\s\-\-password\s/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string2 = /\scollect\sactivedirectory\s\-\-/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string3 = /\/adalanche\/modules\// nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string4 = /activedirectory\/pwns\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string5 = /adalanche\sanalyze/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string6 = /adalanche\scollect/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string7 = /adalanche\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string8 = /Adalanche\.git/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string9 = /adalanche\-collector/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string10 = /adexplorer\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string11 = /HasAutoAdminLogonCredentials/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string12 = /HasSPNNoPreauth/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string13 = /ldap_enums\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string14 = /lkarlslund\/Adalanche/ nocase ascii wide

    condition:
        any of them
}
