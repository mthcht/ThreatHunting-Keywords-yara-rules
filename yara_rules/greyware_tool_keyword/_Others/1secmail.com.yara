rule _1secmail_com
{
    meta:
        description = "Detection patterns for the tool '1secmail.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1secmail.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using the API of 1secmail (temporary email service) could be abused by malicious actors - observed in SafeBreach-Labs/DoubleDrive tool
        // Reference: https://www.1secmail.com/
        $string1 = /www\.1secmail\.com\/api\/v1\/\?action\=/ nocase ascii wide

    condition:
        any of them
}
