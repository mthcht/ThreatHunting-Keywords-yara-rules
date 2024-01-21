rule aeroadmin
{
    meta:
        description = "Detection patterns for the tool 'aeroadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aeroadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string1 = /\saeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string2 = /\/aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string3 = /\\aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string4 = /\\Aeroadmin\.lnk/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string5 = /\\Aeroadmin\\black\.bmp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string6 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string7 = /\\CurrentControlSet\\Services\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string8 = /\\InventoryApplicationFile\\aeroadmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string9 = /\\ProgramData\\Aeroadmin\\/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string10 = /2ef8a13faa44755fab1ac6fb3665cc78f7e7b451/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string11 = /Aeroadmin\sLLC/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string12 = /AeroAdmin\sv4\..{0,1000}\s\(/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string13 = /AeroAdmin\.cpp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string14 = /AEROADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string15 = /Aeroadmin\\Screenshots/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string16 = /AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string17 = /auth11\.aeroadmin\.com/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string18 = /DEFAULT\\Software\\AeroAdmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string19 = /EE54577067550559C4711C9E5E10435807F9DEEE9A5ADB4409CB60A6B0108700/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string20 = /ulm\.aeroadmin\.com\// nocase ascii wide

    condition:
        any of them
}
