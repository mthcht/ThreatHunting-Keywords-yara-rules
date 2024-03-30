rule dig
{
    meta:
        description = "Detection patterns for the tool 'dig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: classic DNS Zone transfer request. The idea behind it is to attempt to duplicate all the DNS records for a given zone (or domain). This is a technique often used by attackers to gather information about the infrastructure of a target organization.
        // Reference: https://linux.die.net/man/1/dig
        $string1 = /dig\s.{0,1000}\saxfr\s.{0,1000}\@/ nocase ascii wide
        // Description: classic DNS Zone transfer request. The idea behind it is to attempt to duplicate all the DNS records for a given zone (or domain). This is a technique often used by attackers to gather information about the infrastructure of a target organization.
        // Reference: https://linux.die.net/man/1/dig
        $string2 = /dig\s.{0,1000}\@.{0,1000}\saxfr/ nocase ascii wide

    condition:
        any of them
}
