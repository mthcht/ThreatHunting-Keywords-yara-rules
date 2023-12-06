rule KCMTicketFormatter
{
    meta:
        description = "Detection patterns for the tool 'KCMTicketFormatter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KCMTicketFormatter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Format SSSD Raw Kerberos Payloads into CCACHE files for use on Windows systems
        // Reference: https://github.com/blacklanternsecurity/KCMTicketFormatter
        $string1 = /\/KCMTicketFormatter/ nocase ascii wide
        // Description: Format SSSD Raw Kerberos Payloads into CCACHE files for use on Windows systems
        // Reference: https://github.com/blacklanternsecurity/KCMTicketFormatter
        $string2 = /\\KCMTicketFormatter/ nocase ascii wide
        // Description: Format SSSD Raw Kerberos Payloads into CCACHE files for use on Windows systems
        // Reference: https://github.com/blacklanternsecurity/KCMTicketFormatter
        $string3 = /Format\sSSSD\sRaw\sKerberos\sPayloads\sinto\sCCACHE\sfiles\./ nocase ascii wide
        // Description: Format SSSD Raw Kerberos Payloads into CCACHE files for use on Windows systems
        // Reference: https://github.com/blacklanternsecurity/KCMTicketFormatter
        $string4 = /KCMTicketFormatter\.py/ nocase ascii wide

    condition:
        any of them
}
