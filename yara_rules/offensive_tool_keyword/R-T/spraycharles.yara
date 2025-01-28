rule spraycharles
{
    meta:
        description = "Detection patterns for the tool 'spraycharles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraycharles"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string1 = " install spraycharles" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string2 = /\sspray\s\-u\s.{0,1000}\s\-H\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sowa/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string3 = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sOffice365/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string4 = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sSmb\s\-H\s/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string5 = /\sspraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string6 = /\/\.spraycharles\/logs/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string7 = /\/\.spraycharles\/out/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string8 = /\/\.spraycharles\:\/root\/\.spraycharles/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string9 = /\/root\/\.local\/bin\/spraycharles/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string10 = /\/spraycharles\.git/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string11 = /\/spraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string12 = /\/tmp\/passwords\.txt/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string13 = /\\spraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string14 = "a89da438ecbe2e8c5f65e2bcbf5d82a84d26ba56dff46eb180c9de213f5a1871" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string15 = /docker\sbuild\s\.\s\-t\sspraycharles/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string16 = "from spraycharles import " nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string17 = "spraycharles analyze " nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string18 = "spraycharles gen extras" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string19 = "spraycharles spray" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string20 = "Tw1sm/spraycharles" nocase ascii wide

    condition:
        any of them
}
