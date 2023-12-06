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
        $string1 = /\sdefault_logins\.txt/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string2 = /\sthc\-hidra/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string3 = /\.\/hydra\s/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string4 = /\.\/xhydra/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string5 = /\/thc\-hydra\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string6 = /common_passwords\.txt/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string7 = /dpl4hydra\s/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string8 = /dpl4hydra\.sh/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string9 = /dpl4hydra_.{0,1000}\.csv/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string10 = /dpl4hydra_.{0,1000}\.tmp/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string11 = /dpl4hydra_linksys/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string12 = /hydra\s\-/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string13 = /hydra\s.{0,1000}\sftp:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string14 = /hydra\s.{0,1000}\shttp\-post\-form\s/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string15 = /hydra\s.{0,1000}\smysql:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string16 = /hydra\s.{0,1000}\sssh:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string17 = /hydra\s.{0,1000}\stelnet:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string18 = /hydra\ssmtp\-enum/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string19 = /hydra\.c/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string20 = /hydra:x:10001:/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string21 = /HYDRA_PROXY_HTTP/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string22 = /hydra\-cobaltstrike/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string23 = /install\shydra\-gtk/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string24 = /pw\-inspector\s\-/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string25 = /pw\-inspector\./ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string26 = /thc\-hydra/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string27 = /thc\-hydra\.git/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string28 = /thc\-hydra\.git/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string29 = /vanhauser\-thc\/thc\-hydra/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string30 = /hydra\s\-/ nocase ascii wide

    condition:
        any of them
}
