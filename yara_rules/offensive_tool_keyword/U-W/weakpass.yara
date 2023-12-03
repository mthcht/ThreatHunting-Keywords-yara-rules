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
        $string1 = /.{0,1000}\/1\/all_in_one\.7z\.torrent.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string2 = /.{0,1000}\/1\/all_in_one_p\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string3 = /.{0,1000}\/1\/all_in_one_w\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string4 = /.{0,1000}\/dicassassin\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string5 = /.{0,1000}\/hashesorg2019\.gz.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string6 = /.{0,1000}\/weakpass\.git.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string7 = /.{0,1000}\/weakpass_2a\.gz.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string8 = /.{0,1000}\/weakpass_3a\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string9 = /.{0,1000}\\online_brute\.gz.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string10 = /.{0,1000}cyclone\.hashesorg\.hashkiller\.combined.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string11 = /.{0,1000}download\.weakpass\.com\/.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string12 = /.{0,1000}github\.io\/weakpass\/generator\/.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string13 = /.{0,1000}https:\/\/weakpass\.com\/.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string14 = /.{0,1000}js\-cracker\-client\/cracker\.js.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string15 = /.{0,1000}online_brute\.gz\.torrent.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string16 = /.{0,1000}weakpass\.com\/crack\-js.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string17 = /.{0,1000}weakpass\.com\/generate.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string18 = /.{0,1000}weakpass\.com\/wordlist\/.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string19 = /.{0,1000}weakpass\/crack\-js.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string20 = /.{0,1000}weakpass_3\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string21 = /.{0,1000}weakpass_3a\.7z\.torrent.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string22 = /.{0,1000}weakpass\-main\..{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string23 = /.{0,1000}wordlists.{0,1000}all_in_one\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string24 = /.{0,1000}xsukax\-Wordlist\-All\.7z.{0,1000}/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string25 = /.{0,1000}zzzteph\/weakpass.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
