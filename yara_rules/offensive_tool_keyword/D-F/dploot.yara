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
        $string1 = /\s\-m\srdrleakdiag\s\-M\smasterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string2 = /\/dploot\.git/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string3 = /dploot\s\-/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string4 = /dploot.*backupkey/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string5 = /dploot.*browser/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string6 = /dploot.*certificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string7 = /dploot.*credentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string8 = /dploot.*machinecertificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string9 = /dploot.*machinecredentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string10 = /dploot.*machinemasterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string11 = /dploot.*machinevaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string12 = /dploot.*masterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string13 = /dploot.*vaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string14 = /dploot.*wifi/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string15 = /dploot_linux_adm64/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string16 = /dploot\-main\.zip/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string17 = /install\sdploot/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string18 = /lsassy\s\-/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string19 = /zblurx\/dploot/ nocase ascii wide

    condition:
        any of them
}