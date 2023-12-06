rule crypto_identifier
{
    meta:
        description = "Detection patterns for the tool 'crypto_identifier' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crypto_identifier"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Crypto tool for pentest and ctf : try to uncipher data using multiple algorithms and block chaining modes. Usefull for a quick check on unknown cipher text and key dictionary
        // Reference: https://github.com/Acceis/crypto_identifier
        $string1 = /crypto_identifier/ nocase ascii wide

    condition:
        any of them
}
