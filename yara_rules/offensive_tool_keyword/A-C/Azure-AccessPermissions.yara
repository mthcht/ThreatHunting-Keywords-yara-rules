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
        $string2 = /AAP\-AddToHighPrivilegePrincipalMap/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string3 = /AAP\-CheckIfMemberOfPrivilegedDirectoryRole/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string4 = /AAP\-DisplayApplicableMFAConditionalAccessPolicyForUserID/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string5 = /AAP\-DisplayHighPrivilegePrincipalMap/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string6 = /AAP\-DisplayNonHighPrivilegedRoleAssignments/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string7 = /AAP\-GetHighPrivilegedDirectoryRoleTemplateMap/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string8 = /Azure\-AccessPermissions\.ps1/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string9 = /Azure\-AccessPermissions\-master/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string10 = /csandker\/Azure\-AccessPermissions/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string11 = /Enumerate\-AllHighPrivilegePrincipals/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string12 = /Enumerate\-MFAStatusOfHighPrivilegePrincipals/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string13 = /Invoke\-AccessCheckForAllGroups/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string14 = /Invoke\-AccessCheckForAllServicePrincipals/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string15 = /Invoke\-AccessCheckForAllUsers/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string16 = /Invoke\-AccessCheckForCurrentUser/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string17 = /Invoke\-AccessCheckForCurrentUser/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string18 = /Invoke\-AccessCheckForGroup/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string19 = /Invoke\-AccessCheckForServicePrincipal/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string20 = /Invoke\-AccessCheckForUser/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string21 = /Invoke\-AllAccessChecks/ nocase ascii wide

    condition:
        any of them
}
