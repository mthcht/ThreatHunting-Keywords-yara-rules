rule OpenSSH_Trojan
{
    meta:
        description = "Detection patterns for the tool 'OpenSSH Trojan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OpenSSH Trojan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: openssh trojan - non existing banner in official OpenSSH - only observed in compromised routers (APT28)
        // Reference: https://www.ic3.gov/Media/News/2024/240227.pdf
        $string1 = /SSH\-2\.0\-OpenSSH_6\.7p2/ nocase ascii wide

    condition:
        any of them
}
