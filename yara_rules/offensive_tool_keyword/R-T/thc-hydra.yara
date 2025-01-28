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
        $string1 = /\sdefault_logins\.txt/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string2 = " thc-hidra"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string3 = /\.\/hydra\s/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string4 = /\.\/xhydra/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string5 = "/hydra -"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string6 = "/thc-hydra/"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string7 = /common_passwords\.txt/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string8 = "dpl4hydra "
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string9 = /dpl4hydra\.sh/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string10 = /dpl4hydra_.{0,1000}\.csv/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string11 = /dpl4hydra_.{0,1000}\.tmp/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string12 = "dpl4hydra_linksys"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string13 = /hydra\s.{0,1000}\sftp\:\/\//
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string14 = /hydra\s.{0,1000}\shttp\-post\-form\s/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string15 = /hydra\s.{0,1000}\smysql\:\/\//
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string16 = /hydra\s.{0,1000}\sssh\:\/\//
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string17 = /hydra\s.{0,1000}\stelnet\:\/\//
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string18 = "hydra smtp-enum"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string19 = "hydra:x:10001:"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string20 = "HYDRA_PROXY_HTTP"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string21 = "hydra-cobaltstrike"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string22 = "install hydra-gtk"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string23 = "pw-inspector -"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string24 = /pw\-inspector\./
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string25 = "thc-hydra"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string26 = /thc\-hydra\.git/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string27 = /thc\-hydra\.git/
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string28 = "vanhauser-thc/thc-hydra"
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string29 = "hydra -"

    condition:
        any of them
}
