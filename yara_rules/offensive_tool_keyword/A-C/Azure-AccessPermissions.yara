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
        $string1 = /.{0,1000}\/Azure\-AccessPermissions\.git.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string2 = /.{0,1000}AAP\-AddToHighPrivilegePrincipalMap.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string3 = /.{0,1000}AAP\-CheckIfMemberOfPrivilegedDirectoryRole.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string4 = /.{0,1000}AAP\-DisplayApplicableMFAConditionalAccessPolicyForUserID.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string5 = /.{0,1000}AAP\-DisplayHighPrivilegePrincipalMap.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string6 = /.{0,1000}AAP\-DisplayNonHighPrivilegedRoleAssignments.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string7 = /.{0,1000}AAP\-GetHighPrivilegedDirectoryRoleTemplateMap.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string8 = /.{0,1000}Azure\-AccessPermissions\.ps1.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string9 = /.{0,1000}Azure\-AccessPermissions\-master.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string10 = /.{0,1000}csandker\/Azure\-AccessPermissions.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string11 = /.{0,1000}Enumerate\-AllHighPrivilegePrincipals.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string12 = /.{0,1000}Enumerate\-MFAStatusOfHighPrivilegePrincipals.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string13 = /.{0,1000}Invoke\-AccessCheckForAllGroups.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string14 = /.{0,1000}Invoke\-AccessCheckForAllServicePrincipals.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string15 = /.{0,1000}Invoke\-AccessCheckForAllUsers.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string16 = /.{0,1000}Invoke\-AccessCheckForCurrentUser.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string17 = /.{0,1000}Invoke\-AccessCheckForCurrentUser.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string18 = /.{0,1000}Invoke\-AccessCheckForGroup.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string19 = /.{0,1000}Invoke\-AccessCheckForServicePrincipal.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string20 = /.{0,1000}Invoke\-AccessCheckForUser.{0,1000}/ nocase ascii wide
        // Description: Easy to use PowerShell script to enumerate access permissions in an Azure Active Directory environment.
        // Reference: https://github.com/csandker/Azure-AccessPermissions
        $string21 = /.{0,1000}Invoke\-AllAccessChecks.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
