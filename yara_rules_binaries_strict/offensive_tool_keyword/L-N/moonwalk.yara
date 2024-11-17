rule moonwalk
{
    meta:
        description = "Detection patterns for the tool 'moonwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "moonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string1 = /\s\-o\smoonwalk/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string2 = /\/\.MOONWALK/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string3 = /\/log_file_timestamps\.json/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string4 = /\/moonwalk\.git/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string5 = /\/moonwalk_darwin/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string6 = /\/v1\.0\.0\/moonwalk_linux/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string7 = /4c368fe58781e363b1176be2a6efcfaaa74432309d1cfc251174a5650debfbe8/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string8 = /62a69abb559cbca8163cb933445bce62a2e73f5dffcf2a77e28f8f64fc1889fd/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string9 = /90873c2ac02c860b3b6ec7cf262ab58504ff187dd9e638bbabef94e985607836/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string10 = /clear_me_from_history\(\)\?/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string11 = /Finish\smoonwalk\sand\sclear\syour\straces/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string12 = /moonwalk\sfinish/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string13 = /moonwalk\sget\s.{0,100}history/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string14 = /moonwalk\sstart/ nocase ascii wide
        // Description: Cover your tracks during Linux Exploitation by leaving zero traces on system logs and filesystem timestamps.
        // Reference: https://github.com/mufeedvh/moonwalk
        $string15 = /mufeedvh\/moonwalk/ nocase ascii wide
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
