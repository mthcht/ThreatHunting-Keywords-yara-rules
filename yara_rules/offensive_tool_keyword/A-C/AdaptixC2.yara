rule AdaptixC2
{
    meta:
        description = "Detection patterns for the tool 'AdaptixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdaptixC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string1 = /\/AdapticClient\.exe/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string2 = /\/AdaptixC2\.git/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string3 = /\\AdapticClient\.exe/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string4 = "9117d2d155a124e050aaf1c64011f5a65198f9dd91289ffcf809f8364740f1d5" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string5 = "99a5f42e-60a8-4f1e-9dff-35443b972707" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string6 = "AdaptixClient/AdaptixClient" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string7 = "Adaptix-Framework/AdaptixC2" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string8 = "AdaptixServer -p" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string9 = "AdaptixServer/adaptixserver" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string10 = "d886eb849d99a52449eb869bdf954644c2d5259db29be9cc757084bf166c42e0" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string11 = /https\:\/\/adaptix\-framework\.gitbook\.io\/adaptix\-framework\/adaptix\-c2\/getting\-starting\// nocase ascii wide

    condition:
        any of them
}
