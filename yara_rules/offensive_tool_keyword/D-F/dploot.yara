rule dploot
{
    meta:
        description = "Detection patterns for the tool 'dploot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dploot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string1 = /.{0,1000}\s\-m\srdrleakdiag\s\-M\smasterkeys.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string2 = /.{0,1000}\/dploot\.git.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string3 = /.{0,1000}dploot\s\-.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string4 = /.{0,1000}dploot.{0,1000}backupkey.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string5 = /.{0,1000}dploot.{0,1000}browser.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string6 = /.{0,1000}dploot.{0,1000}certificates.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string7 = /.{0,1000}dploot.{0,1000}credentials.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string8 = /.{0,1000}dploot.{0,1000}machinecertificates.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string9 = /.{0,1000}dploot.{0,1000}machinecredentials.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string10 = /.{0,1000}dploot.{0,1000}machinemasterkeys.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string11 = /.{0,1000}dploot.{0,1000}machinevaults.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string12 = /.{0,1000}dploot.{0,1000}masterkeys.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string13 = /.{0,1000}dploot.{0,1000}vaults.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string14 = /.{0,1000}dploot.{0,1000}wifi.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string15 = /.{0,1000}dploot_linux_adm64.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string16 = /.{0,1000}dploot\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string17 = /.{0,1000}install\sdploot.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string18 = /.{0,1000}lsassy\s\-.{0,1000}/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string19 = /.{0,1000}zblurx\/dploot.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
