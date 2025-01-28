rule Adamantium_Thief
{
    meta:
        description = "Detection patterns for the tool 'Adamantium-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adamantium-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string1 = /\.exe\sBOOKMARKS/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string2 = /\.exe\sCOOKIES/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string3 = /\.exe\sCREDIT_CARDS/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string4 = /\/Adamantium\-Thief\.git/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string5 = /\/Stealer\.exe/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string6 = /\/Stealer\.sln/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string7 = /\\Stealer\.exe/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string8 = /\\Stealer\.sln/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string9 = /\\Stealer\\modules\\Passwords\.cs/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string10 = /\\Stealer\\Stealer\\modules\\/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string11 = "Adamantium-Thief-master" nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string12 = "Coded by LimerBoy <3" nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string13 = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string14 = "LimerBoy/Adamantium-Thief" nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string15 = /Please\sselect\scommand\s\[PASSWORDS\/HISTORY\/COOKIES\/AUTOFILL\/CREDIT_CARDS\/BOOKMARKS\]/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string16 = /Stealer\.exe\s/ nocase ascii wide
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
