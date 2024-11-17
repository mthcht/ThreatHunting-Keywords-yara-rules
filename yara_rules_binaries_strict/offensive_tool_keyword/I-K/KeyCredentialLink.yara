rule KeyCredentialLink
{
    meta:
        description = "Detection patterns for the tool 'KeyCredentialLink' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyCredentialLink"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string1 = /\s\/domain\:.{0,100}\s\/dc\:.{0,100}\s\/getcredentials\s\/nowrap/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string2 = /\sKeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string3 = /\.exe\sasktgt\s\/user\:.{0,100}\s\/certificate\:.{0,100}\s\/password\:/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string4 = /\/KeyCredentialLink\.git/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string5 = /\/KeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string6 = /\\KeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string7 = /\\Public\\Documents\\DSInternals/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string8 = /1257077a68f9725d863947e0931a44727fceaad6565b73b9f8d873cc3d028e00/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string9 = /5db4c8112942c658a4f14d16fff13781dd705273c0050b2ada09ec79c7cb7c87/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string10 = /Add\-KeyCredentials\s\-target\s/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string11 = /AERTSW50ZXJuYWxzXHg4Nlx2Y3J1bnRpbWUxNDBfdGhyZWFkcy5kbGxQSwECFAAUAAAACAAnnY1YrbP4grERAAA9RQAADwAAAAAAAAAAAAAAAABk7yEARFNJbnRlcm5hbHMuY2F0UEsFBgAAAAAwADAAdRAAAEIBIgAAAA\=\=/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string12 = /Clear\-KeyCredentials\s\-target\s/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string13 = /Leo4j\/KeyCredentialLink/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string14 = /List\-KeyCredentials\s\-target\s/ nocase ascii wide
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
