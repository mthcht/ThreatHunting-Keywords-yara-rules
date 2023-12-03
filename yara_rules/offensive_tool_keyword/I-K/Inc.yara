rule Inc
{
    meta:
        description = "Detection patterns for the tool 'Inc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Inc ransomware
        // Reference: https://github.com/rivitna/Malware
        $string1 = /.{0,1000}\sdelete\sshadow\scopies\sfrom\s.{0,1000}c:\/\s.{0,1000}/ nocase ascii wide
        // Description: Inc ransomware
        // Reference: https://github.com/rivitna/Malware
        $string2 = /.{0,1000}\[.{0,1000}\]\sStarting\sfull\sencryption\sin\s5s.{0,1000}/ nocase ascii wide
        // Description: Inc ransomware
        // Reference: https://github.com/rivitna/Malware
        $string3 = /.{0,1000}PGh0bWw\+DQoJPGhlYWQ\+DQoJCTx0aXRsZT5JbmMuIFJhbnNvbXdhcmU8.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
