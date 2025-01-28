rule GatherContacts
{
    meta:
        description = "Detection patterns for the tool 'GatherContacts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GatherContacts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Burp Suite Extension to pull Employee Names from Google and Bing LinkedIn Search Results.As part of reconnaissance when performing a penetration test. it is often useful to gather employee names that can then be massaged into email addresses and usernames. The usernames may come in handy for performing a password spraying attack for example. One easy way to gather employee names is to use the following Burp Suite Pro extension as described below.
        // Reference: https://github.com/clr2of8/GatherContacts
        $string1 = "clr2of8/GatherContacts" nocase ascii wide

    condition:
        any of them
}
