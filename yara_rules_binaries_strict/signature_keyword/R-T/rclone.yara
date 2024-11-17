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
        $string3 = /Behavior\:Win32\/OFNRclone/ nocase ascii wide
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
        $string18 = /HackTool\:Win64\/FakeRclone/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
