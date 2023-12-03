rule freefilesync
{
    meta:
        description = "Detection patterns for the tool 'freefilesync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "freefilesync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string1 = /.{0,1000}\/FreeFileSync\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string2 = /.{0,1000}\/FreeFileSync_.{0,1000}_Windows_Setup\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string3 = /.{0,1000}\/FreeFileSyncPortable_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string4 = /.{0,1000}\/RealTimeSync\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string5 = /.{0,1000}\\CurrentVersion\\Uninstall\\FreeFileSync_is1.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string6 = /.{0,1000}\\FreeFileSync\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string7 = /.{0,1000}\\FreeFileSync\\Logs\\.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string8 = /.{0,1000}\\FreeFileSync_.{0,1000}_Windows_Setup\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string9 = /.{0,1000}\\FreeFileSyncPortable_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string10 = /.{0,1000}\\Program\sFiles\\FreeFileSync.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string11 = /.{0,1000}\\RealTimeSync\.exe.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string12 = /.{0,1000}\-Command\sAdd\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Program\sFiles\\FreeFileSync\\Bin\\.{0,1000}/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string13 = /.{0,1000}SOFTWARE\\WOW6432Node\\FreeFileSync.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
