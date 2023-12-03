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
        $string1 = /.{0,1000}\sevilginx.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string2 = /.{0,1000}\/evilginx.{0,1000}/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string3 = /.{0,1000}\/gophish\.db.{0,1000}/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string4 = /.{0,1000}\/gophish\/.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string5 = /.{0,1000}evilfeed\.go.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string6 = /.{0,1000}evilginx\-linux.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string7 = /.{0,1000}evilgophish.{0,1000}/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string8 = /.{0,1000}gophish.{0,1000}phish\.go.{0,1000}/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string9 = /.{0,1000}gophish\.go.{0,1000}/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string10 = /.{0,1000}gophish\/gophish.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string11 = /.{0,1000}localhost:1337.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string12 = /.{0,1000}localhost:3333.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string13 = /.{0,1000}lures\screate\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string14 = /.{0,1000}phish_test\.go.{0,1000}/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string15 = /.{0,1000}phishlets\s.{0,1000}/ nocase ascii wide
        // Description: Hiding GoPhish from the boys in blue
        // Reference: https://github.com/puzzlepeaches/sneaky_gophish/
        $string16 = /.{0,1000}sneaky_gophish.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
