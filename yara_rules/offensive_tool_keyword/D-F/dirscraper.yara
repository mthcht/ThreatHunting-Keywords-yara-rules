rule dirscraper
{
    meta:
        description = "Detection patterns for the tool 'dirscraper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirscraper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dirscraper is an OSINT scanning tool which assists penetration testers in identifying hidden. or previously unknown. directories on a domain or subdomain. This helps greatly in the recon stage of pentesting as it provide pentesters with a larger attack surface for the specific domain.
        // Reference: https://github.com/Cillian-Collins/dirscraper
        $string1 = /dirscraper/ nocase ascii wide

    condition:
        any of them
}
