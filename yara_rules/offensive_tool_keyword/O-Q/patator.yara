rule patator
{
    meta:
        description = "Detection patterns for the tool 'patator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "patator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patator was written out of frustration from using Hydra. Medusa. Ncrack. Metasploit modules and Nmap NSE scripts for password guessing attacks. I opted for a different approach in order to not create yet another brute-forcing tool and avoid repeating the same shortcomings. Patator is a multi-threaded tool written in Python. that strives to be more reliable and flexible than his fellow predecessors.
        // Reference: https://github.com/lanjelot/patator
        $string1 = "patator" nocase ascii wide

    condition:
        any of them
}
