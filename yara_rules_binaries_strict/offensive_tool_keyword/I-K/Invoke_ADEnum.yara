rule Invoke_ADEnum
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string1 = " -Recommended -SprayEmptyPasswords" nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string2 = /\$EmptyPasswordUsers/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string3 = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string4 = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string5 = /\$SprayEmptyPasswords/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string6 = /\/Invoke\-ADEnum\.git/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string7 = /\\.{0,100}_AD\-Audit_.{0,100}\.txt/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string8 = /\\Invoke\-ADEnum\\/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string9 = /\\Invoke\-ADEnum\-main/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string10 = /\\krbtgtAccounts\.json/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string11 = /\]\sCollecting\sKrbtgt/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string12 = "27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49" nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string13 = "Find-LocalAdminAccess " nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string14 = "Invoke-ADEnum -" nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string15 = /Invoke\-ADEnum\.ps1/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string16 = "Invoke-ShareHunter " nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string17 = "Leo4j/Invoke-ADEnum" nocase ascii wide
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
