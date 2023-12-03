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
        $string1 = /.{0,1000}\s\-\-authmode\sntlm\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string2 = /.{0,1000}\scollect\sactivedirectory\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string3 = /.{0,1000}\/adalanche\/modules\/.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string4 = /.{0,1000}activedirectory\/pwns\.go.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string5 = /.{0,1000}adalanche\sanalyze.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string6 = /.{0,1000}adalanche\scollect.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string7 = /.{0,1000}adalanche\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string8 = /.{0,1000}Adalanche\.git.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string9 = /.{0,1000}adalanche\-collector.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string10 = /.{0,1000}adexplorer\.go.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string11 = /.{0,1000}HasAutoAdminLogonCredentials.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string12 = /.{0,1000}HasSPNNoPreauth.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string13 = /.{0,1000}ldap_enums\.go.{0,1000}/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string14 = /.{0,1000}lkarlslund\/Adalanche.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
