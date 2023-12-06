rule SMBGhost
{
    meta:
        description = "Detection patterns for the tool 'SMBGhost' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBGhost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple scanner for CVE-2020-0796 - SMBv3 RCE.
        // Reference: https://github.com/ollypwn/SMBGhost
        $string1 = /\/SMBGhost\/scanner\.py/ nocase ascii wide
        // Description: Simple scanner for CVE-2020-0796 - SMBv3 RCE.
        // Reference: https://github.com/ollypwn/SMBGhost
        $string2 = /SMBGhost\.pcap/ nocase ascii wide

    condition:
        any of them
}
