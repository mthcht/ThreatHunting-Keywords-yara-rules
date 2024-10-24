rule gophish
{
    meta:
        description = "Detection patterns for the tool 'gophish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gophish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string1 = /\sevilginx/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string2 = /\/evilginx/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string3 = /\/gophish\.db/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string4 = /\/gophish\// nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string5 = /c121f7d62fa5ecd27c3aaae5737a3de8f2e4def0c182058b6dd824aa92351e9c/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string6 = /evilfeed\.go/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string7 = /evilginx\-linux/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string8 = /evilgophish/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string9 = /gophish.{0,1000}phish\.go/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string10 = /gophish\.go/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string11 = /gophish\/gophish/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string12 = /localhost\:1337/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string13 = /lures\screate\s/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string14 = /phish_test\.go/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string15 = /phishlets\s/ nocase ascii wide
        // Description: Hiding GoPhish from the boys in blue
        // Reference: https://github.com/puzzlepeaches/sneaky_gophish/
        $string16 = /sneaky_gophish/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string17 = /X\-Gophish\-Contact/ nocase ascii wide

    condition:
        any of them
}
