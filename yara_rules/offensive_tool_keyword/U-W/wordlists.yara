rule wordlists
{
    meta:
        description = "Detection patterns for the tool 'wordlists' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string1 = /\sinstall\swordlists/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string2 = /\s\-u\swordlist\s.{0,1000}\swordlist_uniq_sorted/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string3 = /\/amass\/wordlists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string4 = /\/brutespray\// nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string5 = /\/dirbuster\// nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string6 = /\/fb_firstlast\.7z/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string7 = /\/fern\-wifi\-cracker\// nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string8 = /\/rockyou\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string9 = /\/top_mots_combo\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string10 = /\/Web\/decouverte\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string11 = /\/Web\/discovery\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string12 = /\/wikipedia_fr\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string13 = /clem9669_wordlist_medium\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string14 = /clem9669_wordlist_small\.7z/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string15 = /dirb\/wordlists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string16 = /fasttrack\/wordlist\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string17 = /john\/password\.lst/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string18 = /nselib\/data\/passwords\.lst/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string19 = /rockyou\.txt\.gz/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string20 = /sqlmap\/data\/txt\/wordlist\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string21 = /usr\/share\/seclists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string22 = /wfuzz\/wordlist/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string23 = /wordlist_TLAs\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string24 = /wordlist\-probable\.txt/ nocase ascii wide

    condition:
        any of them
}
