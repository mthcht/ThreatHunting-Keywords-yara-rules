rule premiumize_me
{
    meta:
        description = "Detection patterns for the tool 'premiumize.me' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "premiumize.me"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: hosting service abused by attackers
        // Reference: www.premiumize.me
        $string1 = /https\:\/\/www\.premiumize\.me\// nocase ascii wide

    condition:
        any of them
}
