rule adobe_com
{
    meta:
        description = "Detection patterns for the tool 'adobe.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adobe.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Attackers can use adobe.com to masquerade their domain for phishing purposes.
        // Reference: N/A
        $string1 = /https\:\/\/new\.express\.adobe\.com\/publishedV2\/urn\:aaid\:sc\:/ nocase ascii wide
        // Description: Attackers can use adobe.com to masquerade their domain for phishing purposes.
        // Reference: https://www.joesandbox.com/analysis/515360/0/html
        $string2 = /https\:\/\/spark\.adobe\.com\/page\// nocase ascii wide

    condition:
        any of them
}
