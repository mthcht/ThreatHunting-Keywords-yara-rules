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
        $string1 = /.{0,1000}\sinstall\swordlists.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string2 = /.{0,1000}\s\-u\swordlist\s.{0,1000}\swordlist_uniq_sorted.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string3 = /.{0,1000}\/amass\/wordlists.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string4 = /.{0,1000}\/brutespray\/.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string5 = /.{0,1000}\/dirbuster\/.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string6 = /.{0,1000}\/fb_firstlast\.7z.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string7 = /.{0,1000}\/fern\-wifi\-cracker\/.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string8 = /.{0,1000}\/rockyou\.txt.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string9 = /.{0,1000}\/top_mots_combo\.7z.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string10 = /.{0,1000}\/Web\/decouverte\.txt.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string11 = /.{0,1000}\/Web\/discovery\.txt.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string12 = /.{0,1000}\/wikipedia_fr\.7z.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string13 = /.{0,1000}clem9669_wordlist_medium\.7z.{0,1000}/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string14 = /.{0,1000}clem9669_wordlist_small\.7z.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string15 = /.{0,1000}dirb\/wordlists.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string16 = /.{0,1000}fasttrack\/wordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string17 = /.{0,1000}john\/password\.lst.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string18 = /.{0,1000}nselib\/data\/passwords\.lst.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string19 = /.{0,1000}rockyou\.txt\.gz.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string20 = /.{0,1000}sqlmap\/data\/txt\/wordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string21 = /.{0,1000}usr\/share\/seclists.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string22 = /.{0,1000}wfuzz\/wordlist.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string23 = /.{0,1000}wordlist_TLAs\.txt.{0,1000}/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string24 = /.{0,1000}wordlist\-probable\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
