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
        $string1 = /\/CrossC2\-test/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2 = /\/mimipenguin\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string3 = /\/tmp\/c2\-rebind\.so/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string4 = /c2profile\.profile/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string5 = /cc2_keystrokes/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string6 = /cc2_portscan/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string7 = /CCHOST\=127\.0\.0\.1.{0,1000}\/tmp\/c2/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string8 = /crossc2\sdyn\sload/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string9 = /CrossC2\sframework/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string10 = /CrossC2\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string11 = /CrossC2\.git/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string12 = /CrossC2\.Linux/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string13 = /CrossC2\.MacOS/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string14 = /CrossC2\.Win/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string15 = /CrossC2_dev_/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string16 = /CrossC2\-cs/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string17 = /CrossC2\-GithubBot/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string18 = /CrossC2Kit/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string19 = /genCrossC2\s/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string20 = /genCrossC2\.Win\.exe/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string21 = /gloxec\/CrossC2/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string22 = /http\:\/\/127\.0\.0\.1\/CrossC2/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string23 = /http\:\/\/127\.0\.0\.1\:443\/aaaaaaaaa/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string24 = /http\:\/\/127\.0\.0\.1\:443\/bbbbbbbbb/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string25 = /mimipenguin\./ nocase ascii wide

    condition:
        any of them
}
