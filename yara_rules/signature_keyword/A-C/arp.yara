rule arp
{
    meta:
        description = "Detection patterns for the tool 'arp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arp"
        rule_category = "signature_keyword"

    strings:
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string1 = /cmd\.exe\s\/c\sarp\s\-a\s\>\sC\:\\windows\\.{0,1000}\.out\s2\>\&1/ nocase ascii wide

    condition:
        any of them
}
