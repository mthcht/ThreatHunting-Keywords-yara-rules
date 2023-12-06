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
        $string1 = /\.\/kubestroyer/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string2 = /\/Kubestroyer\.git/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string3 = /cmd\/kubestroyer/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string4 = /kubestroyer\s\-t\s/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string5 = /Kubestroyer\@latest/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string6 = /kubestroyer_linux_x64/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string7 = /kubestroyer_macos_arm64/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string8 = /kubestroyer_macos_x64/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string9 = /kubestroyer_windows_x64/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string10 = /Kubestroyer\-master/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string11 = /Rolix44\/Kubestroyer/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string12 = /Starting\sport\sscan\sfor\s/ nocase ascii wide
        // Description: Kubestroyer aims to exploit Kubernetes clusters misconfigurations and be the swiss army knife of your Kubernetes pentests
        // Reference: https://github.com/Rolix44/Kubestroyer
        $string13 = /Trying\sanon\sRCE\susing\s.{0,1000}\sfor\s/ nocase ascii wide

    condition:
        any of them
}
