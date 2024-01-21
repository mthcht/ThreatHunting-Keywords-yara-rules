rule PingRAT
{
    meta:
        description = "Detection patterns for the tool 'PingRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PingRAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: secretly passes Command and Control (C2) traffic through firewalls using ICMP payloads
        // Reference: https://github.com/umutcamliyurt/PingRAT
        $string1 = /\/PingRAT\.git/ nocase ascii wide
        // Description: secretly passes Command and Control (C2) traffic through firewalls using ICMP payloads
        // Reference: https://github.com/umutcamliyurt/PingRAT
        $string2 = /\[\+\]\sICMP\slistener\sstarted\!/ nocase ascii wide
        // Description: secretly passes Command and Control (C2) traffic through firewalls using ICMP payloads
        // Reference: https://github.com/umutcamliyurt/PingRAT
        $string3 = /\\PingRAT\\/ nocase ascii wide
        // Description: secretly passes Command and Control (C2) traffic through firewalls using ICMP payloads
        // Reference: https://github.com/umutcamliyurt/PingRAT
        $string4 = /PingRAT\.exe/ nocase ascii wide
        // Description: secretly passes Command and Control (C2) traffic through firewalls using ICMP payloads
        // Reference: https://github.com/umutcamliyurt/PingRAT
        $string5 = /umutcamliyurt\/PingRAT/ nocase ascii wide

    condition:
        any of them
}
