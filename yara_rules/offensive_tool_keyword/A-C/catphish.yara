rule catphish
{
    meta:
        description = "Detection patterns for the tool 'catphish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catphish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers. Perfect for Red Team engagements.
        // Reference: https://github.com/ring0lab/catphish
        $string1 = /catphish\.rb/ nocase ascii wide

    condition:
        any of them
}
