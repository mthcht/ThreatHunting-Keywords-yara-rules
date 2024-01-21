rule EDRSilencer
{
    meta:
        description = "Detection patterns for the tool 'EDRSilencer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSilencer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string1 = /\sEDRSilencer\.c/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string2 = /\.exe\sblockedr/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string3 = /\/EDRSilencer\.c/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string4 = /\/EDRSilencer\.git/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string5 = /\\EDRSilencer\.c/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string6 = /Add\sWFP\sfilters\sto\sblock\sthe\sIPv4\sand\sIPv6\soutbound\straffic\sof\sa\sspecific\sprocess/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string7 = /Add\sWFP\sfilters\sto\sblock\sthe\sIPv4\sand\sIPv6\soutbound\straffic\sof\sall\sdetected\sEDR\sprocesses/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string8 = /EDRSilencer\.exe/ nocase ascii wide
        // Description: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server
        // Reference: https://github.com/netero1010/EDRSilencer
        $string9 = /netero1010\/EDRSilencer/ nocase ascii wide

    condition:
        any of them
}
