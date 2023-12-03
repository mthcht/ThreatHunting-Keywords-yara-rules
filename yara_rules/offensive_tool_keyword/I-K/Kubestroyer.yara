rule Kubestroyer
{
    meta:
        description = "Detection patterns for the tool 'Kubestroyer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kubestroyer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string1 = /.{0,1000}\.\/kubestroyer.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string2 = /.{0,1000}\/Kubestroyer\.git.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string3 = /.{0,1000}cmd\/kubestroyer.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string4 = /.{0,1000}kubestroyer\s\-t\s.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string5 = /.{0,1000}Kubestroyer\@latest.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string6 = /.{0,1000}kubestroyer_linux_x64.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string7 = /.{0,1000}kubestroyer_macos_arm64.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string8 = /.{0,1000}kubestroyer_macos_x64.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string9 = /.{0,1000}kubestroyer_windows_x64.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string10 = /.{0,1000}Kubestroyer\-master.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string11 = /.{0,1000}Rolix44\/Kubestroyer.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string12 = /.{0,1000}Starting\sport\sscan\sfor\s.{0,1000}/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string13 = /.{0,1000}Trying\sanon\sRCE\susing\s.{0,1000}\sfor\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
