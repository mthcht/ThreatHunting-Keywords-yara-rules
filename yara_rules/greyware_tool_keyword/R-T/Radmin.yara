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
        $string2 = /\/rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string3 = /\\AppData\\Local\\Temp\\.{0,1000}_Radmin_3\..{0,1000}\.zip/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string4 = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string5 = /\\Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string6 = /\\RADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string7 = /\\Radmin\\radmin\.rpb/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string8 = /\\Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string9 = /\\Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string10 = /\\rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string11 = /\\rsetup64\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string12 = /\\rsl\.exe\s\/setup/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string13 = /\\rsl\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string14 = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string15 = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string16 = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string17 = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string18 = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string19 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string20 = /netsh\sadvfirewall\sfirewall\sadd\srule\sname\=\"Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string21 = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string22 = /radmin\s\/connect:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string23 = /Radmin\sServer\sV3/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string24 = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string25 = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string26 = /radmin\.exe.{0,1000}\s\/connect:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string27 = /rserver3\s\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string28 = /rserver3\s\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string29 = /rserver3\.exe.{0,1000}\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string30 = /rserver3\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string31 = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string32 = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide

    condition:
        any of them
}
