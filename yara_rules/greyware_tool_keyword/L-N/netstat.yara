rule netstat
{
    meta:
        description = "Detection patterns for the tool 'netstat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netstat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may attempt to execute recon commands
        // Reference: N/A
        $string1 = /netsat\s\-naop/ nocase ascii wide
        // Description: Adversaries may attempt to execute recon commands
        // Reference: N/A
        $string2 = /netstat\s\-ano/ nocase ascii wide
        // Description: View all active TCP connections and the TCP and UDP ports the host is listening on.
        // Reference: N/A
        $string3 = /netstat\s\-ant/ nocase ascii wide
        // Description: Adversaries may attempt to execute recon commands
        // Reference: N/A
        $string4 = /NETSTAT\.EXE.{0,1000}\s\-ano/ nocase ascii wide

    condition:
        any of them
}
