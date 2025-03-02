rule vssadmin
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string1 = /\.exe\sdelete\sshadows/ nocase ascii wide
        // Description: the command is used to create a new Volume Shadow Copy for a specific volume which can be utilized by an attacker to collect data from the local system
        // Reference: N/A
        $string2 = "vssadmin create shadow /for=C:" nocase ascii wide
        // Description: the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3 = /vssadmin\screate\sshadow\s\/for\=C\:.{0,100}\s\\Temp\\.{0,100}\.tmp/ nocase ascii wide
        // Description: executes a command to delete the targeted PC volume shadow copies so victims cannot restore older unencrypted versions of their files
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string4 = "vssadmin delete shadows /all /quiet" nocase ascii wide
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string5 = "vssadmin delete shadows" nocase ascii wide
        // Description: List shadow copies using vssadmin
        // Reference: N/A
        $string6 = "vssadmin list shadows" nocase ascii wide
        // Description: Deletes all Volume Shadow Copies from the system quietly (without prompts).
        // Reference: N/A
        $string7 = /vssadmin.{0,100}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string8 = /vssadmin.{0,100}resize\sshadowstorage\s\/for\=c\:\s\/on\=c\:\s\/maxsize\=1/ nocase ascii wide
        // Description: the command is used to create a new Volume Shadow Copy for a specific volume which can be utilized by an attacker to collect data from the local system
        // Reference: N/A
        $string9 = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide
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
