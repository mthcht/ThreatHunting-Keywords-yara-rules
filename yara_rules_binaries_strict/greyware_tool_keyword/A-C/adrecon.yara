rule adrecon
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string1 = /\sADRecon\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string2 = /\$base64adrecon/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string3 = /\/ADRecon\.git/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string4 = /\/ADRecon\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string5 = /\[\-\]\sKerberoast/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string6 = /\[Get\-ADRRevertToSelf\]\sToken\simpersonation\ssuccessfully\sreverted/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string7 = /\[Get\-ADR\-UserImpersonation\]\sAlternate\scredentials\ssuccessfully\simpersonated/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string8 = /\\ADRecon\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string9 = /\\ADRecon\-master/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string10 = /\\ADRecon\-Report\.xlsx/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string11 = /\\BitLockerRecoveryKeys\.csv/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string12 = /\\DefaultPasswordPolicy\.csv/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string13 = "309a6b123ebdbb92766addeb8326311b86c26a21eb5cad30c8cde6c237019046" nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string14 = /ADRecon\s.{0,100}\sby\sPrashant\sMahajan\s\(\@prashant3535\)/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string15 = "ADRecon -OutputDir " nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string16 = /ADRecon\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string17 = "adrecon/ADRecon" nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string18 = /ADRecon\-Console\-Log\.txt/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string19 = /ADRecon\-master\.zip/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string20 = "ADRecon-Report-" nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string21 = /\-ADRecon\-Report\.xlsx/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string22 = /Get\-LAPSPasswords\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string23 = "Invoke-ADRecon" nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string24 = "Invoke-UserImpersonation -Credential " nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
