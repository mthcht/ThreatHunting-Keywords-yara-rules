rule tricky_lnk
{
    meta:
        description = "Detection patterns for the tool 'tricky.lnk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tricky.lnk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string1 = /\stricky\.ps1/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string2 = /\stricky\.vbs/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string3 = /\stricky2\.ps1/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string4 = /\/tricky\.lnk\.git/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string5 = /\/tricky\.ps1/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string6 = /\/tricky\.vbs/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string7 = /\/tricky2\.ps1/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string8 = /\\Desktop\\FakeText\.lnk/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string9 = /\\notavirus\.exe/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string10 = /\\tricky\.lnk\\/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string11 = /\\tricky\.vbs/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string12 = /\\tricky2\.ps1/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string13 = "11fcbd067d55ddaa11e622be03a55ea342efe497cbcb14abf4dc410cb5d7a203" nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string14 = "676766b4b6296303a601cf2191da028cc39681fa69b1da408242882f760c849b" nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string15 = "9c9cc73f47b3b509df0845593e6b2f8d900f34772e4aaf3438bb0120303d5670" nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string16 = /xillwillx\/tricky\.lnk/ nocase ascii wide
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
