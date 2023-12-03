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
        $string1 = /.{0,1000}\.exe\s\-t\swl\-extract\.dll\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa\s\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string2 = /.{0,1000}\/whatlicense\.git.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string3 = /.{0,1000}\\whatlicense\-main\\.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string4 = /.{0,1000}\\wl_log\.txt.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string5 = /.{0,1000}\\wl\-lic\.exe.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string6 = /.{0,1000}\\wl\-lic\.pdb.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string7 = /.{0,1000}639EF517\-FCFC\-408E\-9500\-71F0DC0458DB.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string8 = /.{0,1000}CC127443\-2519\-4E04\-8865\-A6887658CDE5.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string9 = /.{0,1000}charlesnathansmith\/whatlicense.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string10 = /.{0,1000}whatlicense\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string11 = /.{0,1000}wl\-lic\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa.{0,1000}/ nocase ascii wide
        // Description: WinLicense key extraction via Intel PIN
        // Reference: https://github.com/charlesnathansmith/whatlicense
        $string12 = /.{0,1000}wl\-lic\s\-h\sHWID\s\-m\smain_hash\s\-d\sregkey2\.dat\s\-r\sregkey2\.rsa.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
