rule weakpass
{
    meta:
        description = "Detection patterns for the tool 'weakpass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "weakpass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string1 = /\/1\/all_in_one\.7z\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string2 = /\/1\/all_in_one_p\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string3 = /\/1\/all_in_one_w\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string4 = /\/dicassassin\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string5 = /\/hashesorg2019\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string6 = /\/weakpass\.git/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string7 = /\/weakpass_2a\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string8 = /\/weakpass_3a\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string9 = /\\online_brute\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string10 = /cyclone\.hashesorg\.hashkiller\.combined/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string11 = /download\.weakpass\.com\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string12 = /github\.io\/weakpass\/generator\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string13 = /https\:\/\/weakpass\.com\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string14 = /js\-cracker\-client\/cracker\.js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string15 = /online_brute\.gz\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string16 = /weakpass\.com\/crack\-js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string17 = /weakpass\.com\/generate/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string18 = /weakpass\.com\/wordlist\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string19 = /weakpass\/crack\-js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string20 = /weakpass_3\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string21 = /weakpass_3a\.7z\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string22 = /weakpass\-main\./ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string23 = /wordlists.{0,1000}all_in_one\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string24 = /xsukax\-Wordlist\-All\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string25 = /zzzteph\/weakpass/ nocase ascii wide

    condition:
        any of them
}
