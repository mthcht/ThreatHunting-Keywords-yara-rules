rule ScriptBlock_Smuggling
{
    meta:
        description = "Detection patterns for the tool 'ScriptBlock-Smuggling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptBlock-Smuggling"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string1 = /\/ScriptBlock\-Smuggling\.git/ nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string2 = /\\ScriptBlock\-Smuggling/ nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string3 = /\\SmugglingCmdlet\.csproj/ nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string4 = /\\SmugglingCmdlet\.sln/ nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string5 = "360F9CE5-D927-46B9-8416-4118D0B68360" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string6 = "4ffe43c71089a936b582e4840c196698a269e62e43a7a48ba3c53124809ab585" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string7 = "5D4E7C1F-4812-4038-9663-6CD277ED9AD4" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string8 = "76dc564506eb2419fffad94ca1eafd192f053261ec01d97848a259d15698d520" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string9 = "779eedf10f0ae805b84e8cc0cd97f4861f0818eefa4ccf087d1c875db1d1c5e3" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string10 = "BC-SECURITY/ScriptBlock-Smuggling" nocase ascii wide
        // Description: SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // Reference: https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $string11 = /ScriptBlockSmuggling\.ps1/ nocase ascii wide
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
