rule asleap
{
    meta:
        description = "Detection patterns for the tool 'asleap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "asleap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string1 = /\/asleap\.exe/ nocase ascii wide
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string2 = /\\asleap\.exe/ nocase ascii wide
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string3 = "apt install asleap" nocase ascii wide
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string4 = /asleap\s\-C\s.{0,1000}\s\-R\s/ nocase ascii wide
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string5 = /asleap\s\-r\s.{0,1000}\.dump\s/ nocase ascii wide
        // Description: Exploiting a serious deficiency in proprietary Cisco LEAP networks
        // Reference: https://github.com/joswr1ght/asleap
        $string6 = /https\:\/\/gitlab\.com\/kalilinux\/packages\/asleap/

    condition:
        any of them
}
