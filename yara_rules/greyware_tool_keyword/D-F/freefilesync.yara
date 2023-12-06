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
        $string1 = /\/FreeFileSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string2 = /\/FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string3 = /\/FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string4 = /\/RealTimeSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string5 = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string6 = /\\FreeFileSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string7 = /\\FreeFileSync\\Logs\\/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string8 = /\\FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string9 = /\\FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string10 = /\\Program\sFiles\\FreeFileSync/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string11 = /\\RealTimeSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string12 = /\-Command\sAdd\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Program\sFiles\\FreeFileSync\\Bin\\/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string13 = /SOFTWARE\\WOW6432Node\\FreeFileSync/ nocase ascii wide

    condition:
        any of them
}
