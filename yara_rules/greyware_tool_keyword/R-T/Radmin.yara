rule Radmin
{
    meta:
        description = "Detection patterns for the tool 'Radmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string1 = /\/Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string2 = /\/Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string3 = /\/Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string4 = /\/Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string5 = /\/rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string6 = /\\AppData\\Local\\Temp\\.{0,1000}_Radmin_3\..{0,1000}\.zip/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string7 = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string8 = /\\Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string9 = /\\RADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string10 = /\\Radmin\\radmin\.rpb/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string11 = /\\Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string12 = /\\Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string13 = /\\Radmin_VPN_1\..{0,1000}\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string14 = /\\rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string15 = /\\rsetup64\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string16 = /\\rsl\.exe\s\/setup/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string17 = /\\rsl\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string18 = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string19 = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string20 = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string21 = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string22 = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string23 = /download\.radmin\.com/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string24 = /download\.radmin\-vpn\.com/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string25 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string26 = /netsh\sadvfirewall\sfirewall\sadd\srule\sname\=\"Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string27 = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string28 = /radmin\s\/connect\:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string29 = /Radmin\sServer\sV3/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string30 = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string31 = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string32 = /radmin\.exe.{0,1000}\s\/connect\:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string33 = /rserver3\s\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string34 = /rserver3\s\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string35 = /rserver3\.exe.{0,1000}\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string36 = /rserver3\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string37 = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string38 = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide

    condition:
        any of them
}
