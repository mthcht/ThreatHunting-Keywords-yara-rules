rule bulletpassview
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string1 = ">BulletsPassView<" nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string2 = /BulletsPassView\.exe/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string3 = /BulletsPassView\.zip/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string4 = /BulletsPassView_setup\.exe/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string5 = /BulletsPassView_x64\.exe/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string6 = "e71cda5e7c018f18aefcdfbce171cfeee7b8d556e5036d8b8f0864efc5f2156b" nocase ascii wide
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
