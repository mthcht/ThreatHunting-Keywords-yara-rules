rule action1
{
    meta:
        description = "Detection patterns for the tool 'action1' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "action1"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string1 = /\/action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string2 = /\\Action1\\7z\.dll/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string3 = /\\Action1\\Agent\\Certificate/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string4 = /\\Action1\\CrashDumps/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string5 = /\\Action1\\package_downloads/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string6 = /\\Action1\\scripts\\Run_PowerShell_/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string7 = /\\action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string8 = /\\ACTION1_AGENT\.EXE\-/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string9 = /\\action1_log_.{0,1000}\.log/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string10 = /\\Windows\\Action1\\scripts\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string11 = /_renamed_by_Action1/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string12 = /a1\-server\-prod\-even\.action1\.com/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string13 = /Action1\sCorporation/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string14 = /Action1\sEndpoint\sSecurity/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string15 = /Action1.{0,1000}\'DestinationPort\'\>22543/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string16 = /Action1\\batch_data\\Run_Script__/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string17 = /Action1\\first_install\.tmp/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string18 = /Action1\\what_is_this\.txt/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string19 = /action1_agent\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string20 = /action1_agent\.exe\.connection/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string21 = /action1_remote\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string22 = /action1_update\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string23 = /C\:\\Windows\\Action1\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string24 = /C\:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Action1/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string25 = /\'Company\'\>Action1\sCorporation/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string26 = /CurrentControlSet\\Services\\A1Agent/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string27 = /https\:\/\/app\.action1\.com\/agent\/.{0,1000}\/Windows\/.{0,1000}\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string28 = /InventoryApplicationFile\\action1_agent\.ex/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string29 = /InventoryApplicationFile\\action1_remote\.e/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string30 = /server\.action1\.com/ nocase ascii wide

    condition:
        any of them
}
