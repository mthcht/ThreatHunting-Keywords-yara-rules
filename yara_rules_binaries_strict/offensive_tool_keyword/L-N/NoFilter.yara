rule NoFilter
{
    meta:
        description = "Detection patterns for the tool 'NoFilter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoFilter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string1 = /\/NoFilter\.cpp/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string2 = /\/NoFilter\.exe/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string3 = /\/NoFilter\.git/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string4 = /\/NoFilter\.sln/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string5 = /\/NoFilter\.vcxproj/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string6 = /\\NoFilter\.cpp/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string7 = /\\NoFilter\.exe/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string8 = /\\NoFilter\.sln/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string9 = /\\NoFilter\.vcxproj/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string10 = /2CFB9E9E\-479D\-4E23\-9A8E\-18C92E06B731/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string11 = /deepinstinct\/NoFilter/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string12 = /NoFilter\.exe\s/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string13 = /NoFilter\-main\.zip/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string14 = /WfpEscalation\.exe/ nocase ascii wide
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
