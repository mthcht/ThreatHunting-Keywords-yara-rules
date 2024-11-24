rule AVKiller
{
    meta:
        description = "Detection patterns for the tool 'AVKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AVKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string1 = /\/AVKiller\.git/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string2 = "1y0n/AVKiller" nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string3 = "6eac306cec3650ed8740d82024380ccaaea2ac4b8f6b55119a9e5fb82485f67f" nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string4 = "ba99e7ff67fb59ab551943030c912a2dfa0c9f1e1bba2c3e53a71aa5348386ec" nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string5 = "dd35d7c7b99d5a0a182ff16546ebee8af08ee92510157d6f02355bae256d6191" nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string6 = /https\:\/\/mp\.weixin\.qq\.com\/s\/GDPAC_9\-Pxfcj_z0_C_ixw/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string7 = /TerminateProcessFromId\(ID\(\\"360rp\.exe\\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string8 = /TerminateProcessFromId\(ID\(\\"360rps\.exe\\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string9 = /TerminateProcessFromId\(ID\(\\"360sd\.exe\\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string10 = /TerminateProcessFromId\(ID\(\\"360tray\.exe\\"\)/ nocase ascii wide
        // Description: forcibly close some anti-virus processes through process injection (taking 360 Security Guard and 360 Anti-Virus as examples)
        // Reference: https://github.com/1y0n/AVKiller
        $string11 = /TerminateProcessFromId\(ID\(\\"ZhuDongFangYu\.exe\\"\)/ nocase ascii wide
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
