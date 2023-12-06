rule Findsploit
{
    meta:
        description = "Detection patterns for the tool 'Findsploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Findsploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Finsploit is a simple bash script to quickly and easily search both local and online exploit databases. This repository also includes copysploit to copy any exploit-db exploit to the current directory and compilesploit to automatically compile and run any C exploit (ie. ./copysploit 1337.c && ./compilesploit 1337.c)
        // Reference: https://github.com/1N3/Findsploit
        $string1 = /Findsploit/ nocase ascii wide

    condition:
        any of them
}
