rule subbrute
{
    meta:
        description = "Detection patterns for the tool 'subbrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "subbrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SubBrute is a community driven project with the goal of creating the fastest. and most accurate subdomain enumeration tool. Some of the magic behind SubBrute is that it uses open resolvers as a kind of proxy to circumvent DNS rate-limiting. This design also provides a layer of anonymity. as SubBrute does not send traffic directly to the targets name servers.
        // Reference: https://github.com/TheRook/subbrute
        $string1 = /subbrute/ nocase ascii wide

    condition:
        any of them
}
