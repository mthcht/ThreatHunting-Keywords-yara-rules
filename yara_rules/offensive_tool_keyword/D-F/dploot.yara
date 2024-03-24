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
        $string3 = /\]\sTriage\sSCCM\sSecrets/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string4 = /decrypt_chrome_password\(/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string5 = /dploot\s\-/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string6 = /dploot\ssccm\s\-d/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string7 = /dploot.{0,1000}backupkey/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string8 = /dploot.{0,1000}browser/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string9 = /dploot.{0,1000}certificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string10 = /dploot.{0,1000}credentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string11 = /dploot.{0,1000}machinecertificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string12 = /dploot.{0,1000}machinecredentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string13 = /dploot.{0,1000}machinemasterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string14 = /dploot.{0,1000}machinevaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string15 = /dploot.{0,1000}masterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string16 = /dploot.{0,1000}vaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string17 = /dploot.{0,1000}wifi/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string18 = /dploot\.lib\.dpapi/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string19 = /dploot\.lib\.smb/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string20 = /dploot\.triage\./ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string21 = /dploot\.triage\.sccm\simport\sSCCMTriage/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string22 = /dploot\/releases\/download\/.{0,1000}\/dploot/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string23 = /dploot_linux_adm64/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string24 = /dploot\-main\.zip/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string25 = /Dump\slooted\sSCCM\ssecrets\sto\sspecified\sdirectory/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string26 = /Dump\sSCCM\ssecrets\sfrom\sWMI\srequests\sresults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string27 = /import\sDPLootSMBConnection/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string28 = /install\sdploot/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string29 = /lsassy\s\-/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string30 = /Password\:Waza1234/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string31 = /zblurx\/dploot/ nocase ascii wide

    condition:
        any of them
}
