rule Azure_AccessPermissions
{
    meta:
        description = "Detection patterns for the tool 'Azure-AccessPermissions' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure-AccessPermissions"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string1 = /\/Azure\-AccessPermissions\.git/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string2 = "AAP-AddToHighPrivilegePrincipalMap" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string3 = "AAP-CheckIfMemberOfPrivilegedDirectoryRole" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string4 = "AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string5 = "AAP-DisplayHighPrivilegePrincipalMap" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string6 = "AAP-DisplayNonHighPrivilegedRoleAssignments" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string7 = "AAP-GetHighPrivilegedDirectoryRoleTemplateMap" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string8 = /Azure\-AccessPermissions\.ps1/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string9 = "Azure-AccessPermissions-master" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string10 = "csandker/Azure-AccessPermissions" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string11 = "Enumerate-AllHighPrivilegePrincipals" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string12 = "Enumerate-MFAStatusOfHighPrivilegePrincipals" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string13 = "Invoke-AccessCheckForAllGroups" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string14 = "Invoke-AccessCheckForAllServicePrincipals" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string15 = "Invoke-AccessCheckForAllUsers" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string16 = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string17 = "Invoke-AccessCheckForCurrentUser" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string18 = "Invoke-AccessCheckForGroup" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string19 = "Invoke-AccessCheckForServicePrincipal" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string20 = "Invoke-AccessCheckForUser" nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string21 = "Invoke-AllAccessChecks" nocase ascii wide
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
