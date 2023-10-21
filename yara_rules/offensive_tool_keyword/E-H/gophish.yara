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
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string5 = /evilfeed\.go/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string6 = /evilginx\-linux/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string7 = /evilgophish/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string8 = /gophish.*phish\.go/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string9 = /gophish\.go/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string10 = /gophish\/gophish/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string11 = /localhost:1337/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string12 = /localhost:3333/ nocase ascii wide
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

    condition:
        any of them
}