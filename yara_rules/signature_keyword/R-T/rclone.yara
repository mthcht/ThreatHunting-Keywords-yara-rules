rule rclone
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "signature_keyword"

    strings:
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string1 = /Behavior\:Linux\/SuspRcloneSpawn\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string2 = /Behavior\:Linux\/SuspRcloneSpawn\.B/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string3 = "Behavior:Win32/OFNRclone" nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string4 = /Behavior\:Win32\/PShellRclone\.SA/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string5 = /Behavior\:Win32\/RcloneConf\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string6 = /Behavior\:Win32\/RcloneExfil\.S/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string7 = /Behavior\:Win32\/RcloneExfil\.SA/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string8 = /Behavior\:Win32\/RcloneMega\.SA\!Ofn/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string9 = /Behavior\:Win32\/RcloneMega\.SA/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string10 = /Behavior\:Win32\/RcloneSusExec\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string11 = /Behavior\:Win32\/RcloneSusTLD\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string12 = /Behavior\:Win32\/RcloneUAgent\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string13 = /Behavior\:Win32\/RenamedToolRclone\.SA/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string14 = /Behavior\:Win32\/SuspRclone\.A/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string15 = /Behavior\:Win32\/SuspRclone\.B/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string16 = /Behavior\:Win32\/SuspRclone\.C/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string17 = /Behavior\:Win32\/SuspRclone\.D/ nocase ascii wide
        // Description: Rclone is a command line program for syncing files with cloud storage services - abused by a lot of ransomware groups
        // Reference: https://github.com/rclone/rclone
        $string18 = "HackTool:Win64/FakeRclone" nocase ascii wide

    condition:
        any of them
}
