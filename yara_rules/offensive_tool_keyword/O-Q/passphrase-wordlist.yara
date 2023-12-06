rule passphrase_wordlist
{
    meta:
        description = "Detection patterns for the tool 'passphrase-wordlist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passphrase-wordlist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This project includes a massive wordlist of phrases (over 20 million) and two hashcat rule files for GPU-based cracking. The rules will create over 1.000 permutations of each phase.
        // Reference: https://github.com/initstring/passphrase-wordlist
        $string1 = /passphrase\-wordlist/ nocase ascii wide

    condition:
        any of them
}
