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
        $string1 = /.{0,1000}\/GoodSync\-vsub\-Setup\.exe.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string2 = /.{0,1000}\\GoodSync\-2.{0,1000}\-.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string3 = /.{0,1000}\\GoodSync\-vsub\-Setup\.exe.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string4 = /.{0,1000}\\Siber\sSystems\\GoodSync\\.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string5 = /.{0,1000}\\Users\\.{0,1000}\\AppData\\Local\\GoodSync.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string6 = /.{0,1000}Copy\sNew\s.{0,1000}gdrive:\/\/www\.googleapis\.com\/GS_Sync\/.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string7 = /.{0,1000}Copy\sNew\s.{0,1000}sftp:\/\/.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string8 = /.{0,1000}GoodSync\sServer.{0,1000}/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string9 = /.{0,1000}GoodSync\-vsub\-2Go\-Setup\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
