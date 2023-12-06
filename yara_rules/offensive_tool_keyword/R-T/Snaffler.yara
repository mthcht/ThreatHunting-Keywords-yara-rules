rule Snaffler
{
    meta:
        description = "Detection patterns for the tool 'Snaffler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Snaffler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string1 = /\ssnaffler\.log/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string2 = /\/ShareFinder\.cs/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string3 = /\/SnaffCon\.cs/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string4 = /\/SnaffCon\/Snaffler/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string5 = /\/SnaffCore\// nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string6 = /\/snafflertest\// nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string7 = /\/TreeWalker\.cs/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string8 = /SnaffCon\/Snaffler/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string9 = /SnaffCore\.csproj/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string10 = /SnaffCore\/ActiveDirectory/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string11 = /SnaffCore\/Classifiers/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string12 = /SnaffCore\/Concurrency/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string13 = /SnaffCore\/Config/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string14 = /SnaffCore\/ShareFind/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string15 = /SnaffCore\/TreeWalk/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string16 = /Snaffler\.csproj/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string17 = /snaffler\.exe/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string18 = /snaffler\.exe/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string19 = /snaffler\.log/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string20 = /Snaffler\.sln/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string21 = /Snaffler\.sln/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string22 = /SnafflerMessage\.cs/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string23 = /SnafflerMessageType\.cs/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string24 = /UltraSnaffCore\.csproj/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string25 = /UltraSnaffler\.sln/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string26 = /UltraSnaffler\.sln/ nocase ascii wide

    condition:
        any of them
}
