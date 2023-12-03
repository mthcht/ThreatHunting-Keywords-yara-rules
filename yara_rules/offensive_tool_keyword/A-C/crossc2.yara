rule crossc2
{
    meta:
        description = "Detection patterns for the tool 'crossc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crossc2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1 = /.{0,1000}\/CrossC2\-test.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2 = /.{0,1000}\/mimipenguin\/.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string3 = /.{0,1000}\/tmp\/c2\-rebind\.so.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string4 = /.{0,1000}c2profile\.profile.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string5 = /.{0,1000}cc2_keystrokes.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string6 = /.{0,1000}cc2_portscan.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string7 = /.{0,1000}CCHOST\=127\.0\.0\.1.{0,1000}\/tmp\/c2.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string8 = /.{0,1000}crossc2\sdyn\sload.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string9 = /.{0,1000}CrossC2\sframework.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string10 = /.{0,1000}CrossC2\.cna.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string11 = /.{0,1000}CrossC2\.git.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string12 = /.{0,1000}CrossC2\.Linux.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string13 = /.{0,1000}CrossC2\.MacOS.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string14 = /.{0,1000}CrossC2\.Win.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string15 = /.{0,1000}CrossC2_dev_.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string16 = /.{0,1000}CrossC2\-cs.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string17 = /.{0,1000}CrossC2\-GithubBot.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string18 = /.{0,1000}CrossC2Kit/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string19 = /.{0,1000}genCrossC2\s.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string20 = /.{0,1000}genCrossC2\.Win\.exe.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string21 = /.{0,1000}gloxec\/CrossC2.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string22 = /.{0,1000}http:\/\/127\.0\.0\.1\/CrossC2.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string23 = /.{0,1000}http:\/\/127\.0\.0\.1:443\/aaaaaaaaa.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string24 = /.{0,1000}http:\/\/127\.0\.0\.1:443\/bbbbbbbbb.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string25 = /.{0,1000}mimipenguin\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
