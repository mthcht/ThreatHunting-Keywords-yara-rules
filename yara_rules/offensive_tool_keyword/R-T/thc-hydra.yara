rule thc_hydra
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string1 = /.{0,1000}\sdefault_logins\.txt.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string2 = /.{0,1000}\sthc\-hidra.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string3 = /.{0,1000}\.\/hydra\s.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string4 = /.{0,1000}\.\/xhydra.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string5 = /.{0,1000}\/thc\-hydra\/.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string6 = /.{0,1000}common_passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string7 = /.{0,1000}dpl4hydra\s.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string8 = /.{0,1000}dpl4hydra\.sh.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string9 = /.{0,1000}dpl4hydra_.{0,1000}\.csv.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string10 = /.{0,1000}dpl4hydra_.{0,1000}\.tmp.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string11 = /.{0,1000}dpl4hydra_linksys.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string12 = /.{0,1000}hydra\s\-.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string13 = /.{0,1000}hydra\s.{0,1000}\sftp:\/\/.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string14 = /.{0,1000}hydra\s.{0,1000}\shttp\-post\-form\s.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string15 = /.{0,1000}hydra\s.{0,1000}\smysql:\/\/.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string16 = /.{0,1000}hydra\s.{0,1000}\sssh:\/\/.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string17 = /.{0,1000}hydra\s.{0,1000}\stelnet:\/\/.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string18 = /.{0,1000}hydra\ssmtp\-enum.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string19 = /.{0,1000}hydra\.c.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string20 = /.{0,1000}hydra:x:10001:.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string21 = /.{0,1000}HYDRA_PROXY_HTTP.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string22 = /.{0,1000}hydra\-cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string23 = /.{0,1000}install\shydra\-gtk.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string24 = /.{0,1000}pw\-inspector\s\-.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string25 = /.{0,1000}pw\-inspector\..{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string26 = /.{0,1000}thc\-hydra.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string27 = /.{0,1000}thc\-hydra\.git.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string28 = /.{0,1000}thc\-hydra\.git.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string29 = /.{0,1000}vanhauser\-thc\/thc\-hydra.{0,1000}/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string30 = /hydra\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
