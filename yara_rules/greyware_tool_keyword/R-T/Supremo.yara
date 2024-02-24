rule Supremo
{
    meta:
        description = "Detection patterns for the tool 'Supremo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supremo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string1 = /\sstart\sSupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string2 = /\sSupremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string3 = /\/Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string4 = /\\\\\.\\pipe\\Supremo/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string5 = /\\Control\\SafeBoot\\Network\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string6 = /\\CurrentControlSet\\Services\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string7 = /\\Program\sFiles\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string8 = /\\ProgramData\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string9 = /\\SOFTWARE\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string10 = /\\Software\\Supremo\\Printer\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string11 = /\\SOFTWARE\\WOW6432Node\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string12 = /\\Supremo\sRemote\sPrinter\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string13 = /\\Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string14 = /\\SUPREMO\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string15 = /\\Supremo_Client_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string16 = /\\Supremo_Helper_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string17 = /\\Supremo_Service/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string18 = /\\SupremoHelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string19 = /\\SupremoRemoteDesktop\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string20 = /\\Temp\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string21 = /application\/x\-supremo/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string22 = /HKCR\\supremo\\shell\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string23 = /supremo\sremote\scontrol/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string24 = /Supremo\.00\.Client\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string25 = /Supremo\.00\.FileTransfer\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string26 = /Supremo\.exe\s/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string27 = /supremogw.{0,1000}\.nanosystems\.it/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string28 = /supremohelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string29 = /SupremoRemoteDesktop\\History\.txt/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string30 = /SupremoService\.00\.Service\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string31 = /SupremoService\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string32 = /SupremoSystem\.exe/ nocase ascii wide

    condition:
        any of them
}
