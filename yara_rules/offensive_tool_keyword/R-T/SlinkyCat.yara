rule SlinkyCat
{
    meta:
        description = "Detection patterns for the tool 'SlinkyCat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SlinkyCat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string1 = /\/SlinkyCat\.git/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string2 = /DNet\-EnumerateAllDomainUserAccounts/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string3 = /DNet\-ListAccountsByDescription/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string4 = /DNet\-ListDomainUserAccountsWithCompletedADDescription/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string5 = /DNet\-ListUsersInDomainAdminsGroup/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string6 = /EnumerateAllDomainControllers/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string7 = /FindAdminAccessComputers/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string8 = /Invoke\-SlinkyCat/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string9 = /LaresLLC\/SlinkyCat/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string10 = /ListAccountsWithSPN/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string11 = /ListDescriptionContainsPass/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string12 = /ListDomainAdmins/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string13 = /ListDomainGroupsLocalAdmin/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string14 = /ListNeverLoggedInAccounts/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string15 = /ListPasswordNeverExpire/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string16 = /ListUsersLastPasswordChange/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string17 = /ListUsersNoPasswordRequired/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string18 = /ListUsersPasswordMustChange/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string19 = /ListUsersPasswordNotChanged/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string20 = /output\/AccountsWithSPN\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string21 = /output\/AdminAccessComputers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string22 = /output\/AllDomainControllers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string23 = /output\/AllDomainGroups\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string24 = /output\/AllDomainHosts\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string25 = /output\/AllDomainUserAccounts\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string26 = /output\/AllDomainUsers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string27 = /output\/AllServers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string28 = /output\/AllServers2k12\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string29 = /output\/AllServers2k16\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string30 = /output\/AllServers2k19\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string31 = /output\/AllServers2k22\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string32 = /output\/AllServers2k8\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string33 = /output\/AllTrusts\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string34 = /output\/CompletedDescriptionField\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string35 = /output\/DescriptionContainsPass\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string36 = /output\/DNETAccountsByDescription\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string37 = /output\/DomainAdmins\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string38 = /output\/DomainGroupsLocalAdmin\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string39 = /output\/DomainUserAccountsWithCompletedADDescription\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string40 = /output\/ExchangeServers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string41 = /output\/NeverLoggedInAccounts\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string42 = /output\/NonDCWindows10Computers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string43 = /output\/NonDCWindows11Computers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string44 = /output\/NonDCWindows7Computers\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string45 = /output\/PasswordNeverExpire\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string46 = /output\/RDPMachines\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string47 = /output\/UsersInDomainAdminsGroup\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string48 = /output\/UsersLastPasswordChange\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string49 = /output\/UsersNoPasswordRequired\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string50 = /output\/UsersPasswordMustChange\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string51 = /output\/UsersPasswordNotChanged\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string52 = /output\/WinRMMachines\.txt/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string53 = /SlinkyCat\.ps1/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string54 = /SlinkyCat\-main/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string55 = /System\.DirectoryServices\.AccountManagement\.GroupPrincipal.{0,1000}FindByIdentity.{0,1000}D/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string56 = /TestWinRMMachines/ nocase ascii wide

    condition:
        any of them
}
