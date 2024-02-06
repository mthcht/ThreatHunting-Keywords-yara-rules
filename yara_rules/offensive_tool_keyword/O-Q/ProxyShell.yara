rule ProxyShell
{
    meta:
        description = "Detection patterns for the tool 'ProxyShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxyShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Microsoft Exchange Servers exploits - ProxyLogon and ProxyShell  CVE-2021-27065 CVE-2021-34473 CVE-2021-34523 CVE-2021-31207
        // Reference: https://www.cert.ssi.gouv.fr/uploads/ANSSI_TLPWHITE_ProxyShell_ProxyLogon_Sigma_yml.txt
        $string1 = /New\-MailBoxExportRequest\s\-Mailbox\s.{0,1000}\@.{0,1000}\s\-FilePath\s.{0,1000}\.aspx/ nocase ascii wide
        // Description: Microsoft Exchange Servers exploits - ProxyLogon and ProxyShell  CVE-2021-27065 CVE-2021-34473 CVE-2021-34523 CVE-2021-31207
        // Reference: https://www.cert.ssi.gouv.fr/uploads/ANSSI_TLPWHITE_ProxyShell_ProxyLogon_Sigma_yml.txt
        $string2 = /Set\-OabVirtualDirectory\s\-ExternalUrl\s\'http.{0,1000}\:\/\/.{0,1000}function\sPage_Load\(\)\{.{0,1000}\}\<\/script\>/ nocase ascii wide

    condition:
        any of them
}
