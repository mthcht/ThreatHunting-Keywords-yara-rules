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
        $string1 = /.{0,1000}\ssnaffler\.log.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string2 = /.{0,1000}\/ShareFinder\.cs.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string3 = /.{0,1000}\/SnaffCon\.cs.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string4 = /.{0,1000}\/SnaffCon\/Snaffler.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string5 = /.{0,1000}\/SnaffCore\/.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string6 = /.{0,1000}\/snafflertest\/.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string7 = /.{0,1000}\/TreeWalker\.cs.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string8 = /.{0,1000}SnaffCon\/Snaffler.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string9 = /.{0,1000}SnaffCore\.csproj.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string10 = /.{0,1000}SnaffCore\/ActiveDirectory.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string11 = /.{0,1000}SnaffCore\/Classifiers.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string12 = /.{0,1000}SnaffCore\/Concurrency.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string13 = /.{0,1000}SnaffCore\/Config.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string14 = /.{0,1000}SnaffCore\/ShareFind.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string15 = /.{0,1000}SnaffCore\/TreeWalk.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string16 = /.{0,1000}Snaffler\.csproj.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string17 = /.{0,1000}snaffler\.exe.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string18 = /.{0,1000}snaffler\.exe.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string19 = /.{0,1000}snaffler\.log.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string20 = /.{0,1000}Snaffler\.sln.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string21 = /.{0,1000}Snaffler\.sln.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string22 = /.{0,1000}SnafflerMessage\.cs.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string23 = /.{0,1000}SnafflerMessageType\.cs.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string24 = /.{0,1000}UltraSnaffCore\.csproj.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string25 = /.{0,1000}UltraSnaffler\.sln.{0,1000}/ nocase ascii wide
        // Description: Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment)
        // Reference: https://github.com/SnaffCon/Snaffler
        $string26 = /.{0,1000}UltraSnaffler\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
