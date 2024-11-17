rule grep
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string1 = /grep\s\-.{0,100}\s.{0,100}DBPassword/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /grep\s.{0,100}password\s\/var\/www/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string3 = /grep\s.{0,100}password\..{0,100}\s\/etc\/.{0,100}\.conf/ nocase ascii wide
        // Description: Look for users with a UID of 0
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4 = /grep\s\:0\:\s\/etc\/passwd/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string5 = /grep\s\-i\spass\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: https://gtfobins.github.io/
        $string6 = /grep\s\-i\suser\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string7 = /grep\s\-R\sdb_passwd/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string8 = /grep\s\-roiE\s.{0,100}password/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /grep.{0,100}\|pwd\=\|passwd\=\|password\=/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /grep.{0,100}password\|pwd\|pass/ nocase ascii wide
        // Description: search for passwords in memory and core dumps
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11 = /strings\s\-n\s.{0,100}\s\/dev\/mem\s\|\sgrep\s\-i\spass/ nocase ascii wide
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
