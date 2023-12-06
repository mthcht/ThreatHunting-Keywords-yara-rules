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
        $string2 = /\\GoodSync\-2.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string3 = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string4 = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string5 = /\\Users\\.{0,1000}\\AppData\\Local\\GoodSync/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string6 = /Copy\sNew\s.{0,1000}gdrive:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string7 = /Copy\sNew\s.{0,1000}sftp:\/\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string8 = /GoodSync\sServer/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string9 = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide

    condition:
        any of them
}
