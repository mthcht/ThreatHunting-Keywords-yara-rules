rule PayGen
{
    meta:
        description = "Detection patterns for the tool 'PayGen' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PayGen"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string1 = /\/signer\-exe\.py/ nocase ascii wide
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string2 = /PayGen.{0,1000}python3\sgenerate\.py/ nocase ascii wide
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string3 = /shellcode\-exec\.ps1/ nocase ascii wide
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string4 = /shellcode\-runner\.py/ nocase ascii wide
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string5 = /youhacker55\/PayGen/ nocase ascii wide
        // Description: FUD metasploit Persistence RAT
        // Reference: https://github.com/youhacker55/PayGen
        $string6 = /cd\sPayGen/ nocase ascii wide

    condition:
        any of them
}
