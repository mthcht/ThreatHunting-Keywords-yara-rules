rule whatlicense
{
    meta:
        description = "Detection patterns for the tool 'whatlicense' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whatlicense"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string1 = /\.exe\s\-t\swl\-extract\.dll\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa\s\-.{0,1000}\.exe/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string2 = /\/whatlicense\.git/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string3 = /\\whatlicense\-main\\/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string4 = /\\wl_log\.txt/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string5 = /\\wl\-lic\.exe/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string6 = /\\wl\-lic\.pdb/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string7 = /639EF517\-FCFC\-408E\-9500\-71F0DC0458DB/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string8 = /CC127443\-2519\-4E04\-8865\-A6887658CDE5/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string9 = /charlesnathansmith\/whatlicense/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string10 = /whatlicense\-main\.zip/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string11 = /wl\-lic\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string12 = /wl\-lic\s\-h\sHWID\s\-m\smain_hash\s\-d\sregkey2\.dat\s\-r\sregkey2\.rsa/ nocase ascii wide

    condition:
        any of them
}
