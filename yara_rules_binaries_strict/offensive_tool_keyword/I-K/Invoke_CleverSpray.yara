rule Invoke_CleverSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-CleverSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-CleverSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string1 = /\$AllCurrentPwdDiscovered/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string2 = /\$TotalNbCurrentPwdDiscovered/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string3 = /\/Invoke\-CleverSpray\.git/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string4 = /\[\!\]\sPassword\sspraying\swill\sbe\sconducted/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string5 = /\[\!\]\sThe\spassword\s.{0,100}\swill\sbe\ssprayed\son\stargeted\suser\saccounts\shaving/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string6 = /fdb1df0047a31328f0796bd07caf642efc35651ad78389025eb5afa2748bcd04/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string7 = /Invoke\-CleverSpray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string8 = /Invoke\-CleverSpray\.ps1/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string9 = /Please\suse\sthe\s\-Password\soption\sto\sspecify\sa\sunique\spassword\sto\sspray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string10 = /Please\suse\sthe\s\-User\soption\sto\sspecify\sa\sunique\susername\sto\sspray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string11 = /wavestone\-cdt\/Invoke\-CleverSpray/ nocase ascii wide
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
