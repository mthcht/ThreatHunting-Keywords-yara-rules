rule Ask4Creds
{
    meta:
        description = "Detection patterns for the tool 'Ask4Creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ask4Creds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string1 = /\sAsk4Creds\.ps1/ nocase ascii wide
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string2 = /\/Ask4Creds\.git/ nocase ascii wide
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string3 = /\/Ask4Creds\.ps1/ nocase ascii wide
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string4 = /\\Ask4Creds\.ps1/ nocase ascii wide
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string5 = "d3924d3bf6f59335a1e5453d80eaaa7404cea2e342105c3e69ddfb943aeb29c6" nocase ascii wide
        // Description: Prompt User for credentials
        // Reference: https://github.com/Leo4j/Ask4Creds
        $string6 = "Leo4j/Ask4Creds" nocase ascii wide

    condition:
        any of them
}
