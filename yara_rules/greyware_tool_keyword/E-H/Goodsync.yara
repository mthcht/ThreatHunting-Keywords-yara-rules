rule Goodsync
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string1 = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string2 = /\\DIRECTORY\\BACKGROUND\\SHELL\\GOODSYNC/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string3 = /\\GoodSync\-2.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string4 = /\\GOODSYNC2GO\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string5 = /\\GOODSYNC2GO\-V.{0,1000}\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string6 = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string7 = /\\gs\-runner\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string8 = /\\GS\-SERVER\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string9 = /\\Program\sFiles\\SIBER\sSYSTEMS\\GOODSYNC\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string10 = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string11 = /\\Users\\.{0,1000}\\AppData\\Local\\GoodSync/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string12 = /\>GoodSync\</ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string13 = /\>gs\-runner\.exe\</ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string14 = /Copy\sNew\s.{0,1000}gdrive\:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string15 = /Copy\sNew\s.{0,1000}sftp\:\/\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string16 = /GoodSync\sServer/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string17 = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string18 = /mediator\.goodsync\.com/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string19 = /temp.{0,1000}\\gsync\.exe/ nocase ascii wide

    condition:
        any of them
}
