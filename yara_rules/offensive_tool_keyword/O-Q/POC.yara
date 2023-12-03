rule poc
{
    meta:
        description = "Detection patterns for the tool 'poc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string1 = /.{0,1000}\sRCE\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Exploit for the CVE-2023-23399
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string2 = /.{0,1000}\/CVE\-.{0,1000}_EXPLOIT_0DAY\/.{0,1000}/ nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string3 = /.{0,1000}\/Hashi0x\/.{0,1000}/ nocase ascii wide
        // Description: Simple PoC in PowerShell for CVE-2023-23397
        // Reference: https://github.com/ka7ana/CVE-2023-23397
        $string4 = /.{0,1000}\/ka7ana\/CVE.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Exploit for the CVE-2023-23397
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string5 = /.{0,1000}\/MsgKitTestTool\/.{0,1000}/ nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string6 = /.{0,1000}\/PoC\-CVE\-2023\-21554.{0,1000}/ nocase ascii wide
        // Description: Exploit for the CVE-2023-23398
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string7 = /.{0,1000}\/sqrtZeroKnowledge\/CVE\-.{0,1000}/ nocase ascii wide
        // Description: Simple and dirty PoC of the CVE-2023-23397 vulnerability impacting the Outlook thick client.
        // Reference: https://github.com/Trackflaw/CVE-2023-23397
        $string8 = /.{0,1000}\/Trackflaw\/CVE.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string9 = /.{0,1000}cve\-2023\-21554\.nse.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
