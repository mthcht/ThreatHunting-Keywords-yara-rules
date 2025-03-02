rule nping
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "signature_keyword"

    strings:
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string1 = /HackTool\:Linux\/ExfiltrationNping\./ nocase ascii wide

    condition:
        any of them
}
