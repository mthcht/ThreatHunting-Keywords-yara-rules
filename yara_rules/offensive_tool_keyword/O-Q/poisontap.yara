rule poisontap
{
    meta:
        description = "Detection patterns for the tool 'poisontap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poisontap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoisonTap - siphons cookies. exposes internal router & installs web backdoor on locked computers
        // Reference: https://github.com/samyk/poisontap
        $string1 = /poisontap/ nocase ascii wide

    condition:
        any of them
}
