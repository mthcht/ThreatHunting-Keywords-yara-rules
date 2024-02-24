rule canarytokens_com
{
    meta:
        description = "Detection patterns for the tool 'canarytokens.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canarytokens.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: free honeypot detection tokens but also abused by attacker for payload callback confirmation
        // Reference: http://canarytokens.com
        $string1 = /http\:\/\/canarytokens\.com\/.{0,1000}\// nocase ascii wide

    condition:
        any of them
}
