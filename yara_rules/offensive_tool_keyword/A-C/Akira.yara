rule Akira
{
    meta:
        description = "Detection patterns for the tool 'Akira' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Akira"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Akira ransomware Windows payload
        // Reference: https://github.com/rivitna/Malware
        $string1 = /.{0,1000}\s:Failed\sto\smake\sfull\sencrypt.{0,1000}/ nocase ascii wide
        // Description: Akira ransomware Windows payload
        // Reference: https://github.com/rivitna/Malware
        $string2 = /.{0,1000}Paste\sthis\slink\s\-\shttps:\/\/akira.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
