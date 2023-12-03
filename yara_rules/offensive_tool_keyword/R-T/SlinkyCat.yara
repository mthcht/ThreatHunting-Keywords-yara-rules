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
        $string1 = /.{0,1000}\/SlinkyCat\.git.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string2 = /.{0,1000}DNet\-EnumerateAllDomainUserAccounts.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string3 = /.{0,1000}DNet\-ListAccountsByDescription.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string4 = /.{0,1000}DNet\-ListDomainUserAccountsWithCompletedADDescription.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string5 = /.{0,1000}DNet\-ListUsersInDomainAdminsGroup.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string6 = /.{0,1000}EnumerateAllDomainControllers.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string7 = /.{0,1000}FindAdminAccessComputers.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string8 = /.{0,1000}Invoke\-SlinkyCat.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string9 = /.{0,1000}LaresLLC\/SlinkyCat.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string10 = /.{0,1000}ListAccountsWithSPN.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string11 = /.{0,1000}ListDescriptionContainsPass.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string12 = /.{0,1000}ListDomainAdmins.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string13 = /.{0,1000}ListDomainGroupsLocalAdmin.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string14 = /.{0,1000}ListNeverLoggedInAccounts.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string15 = /.{0,1000}ListPasswordNeverExpire.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string16 = /.{0,1000}ListUsersLastPasswordChange.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string17 = /.{0,1000}ListUsersNoPasswordRequired.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string18 = /.{0,1000}ListUsersPasswordMustChange.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string19 = /.{0,1000}ListUsersPasswordNotChanged.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string20 = /.{0,1000}output\/AccountsWithSPN\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string21 = /.{0,1000}output\/AdminAccessComputers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string22 = /.{0,1000}output\/AllDomainControllers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string23 = /.{0,1000}output\/AllDomainGroups\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string24 = /.{0,1000}output\/AllDomainHosts\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string25 = /.{0,1000}output\/AllDomainUserAccounts\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string26 = /.{0,1000}output\/AllDomainUsers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string27 = /.{0,1000}output\/AllServers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string28 = /.{0,1000}output\/AllServers2k12\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string29 = /.{0,1000}output\/AllServers2k16\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string30 = /.{0,1000}output\/AllServers2k19\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string31 = /.{0,1000}output\/AllServers2k22\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string32 = /.{0,1000}output\/AllServers2k8\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string33 = /.{0,1000}output\/AllTrusts\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string34 = /.{0,1000}output\/CompletedDescriptionField\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string35 = /.{0,1000}output\/DescriptionContainsPass\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string36 = /.{0,1000}output\/DNETAccountsByDescription\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string37 = /.{0,1000}output\/DomainAdmins\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string38 = /.{0,1000}output\/DomainGroupsLocalAdmin\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string39 = /.{0,1000}output\/DomainUserAccountsWithCompletedADDescription\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string40 = /.{0,1000}output\/ExchangeServers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string41 = /.{0,1000}output\/NeverLoggedInAccounts\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string42 = /.{0,1000}output\/NonDCWindows10Computers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string43 = /.{0,1000}output\/NonDCWindows11Computers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string44 = /.{0,1000}output\/NonDCWindows7Computers\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string45 = /.{0,1000}output\/PasswordNeverExpire\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string46 = /.{0,1000}output\/RDPMachines\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string47 = /.{0,1000}output\/UsersInDomainAdminsGroup\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string48 = /.{0,1000}output\/UsersLastPasswordChange\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string49 = /.{0,1000}output\/UsersNoPasswordRequired\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string50 = /.{0,1000}output\/UsersPasswordMustChange\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string51 = /.{0,1000}output\/UsersPasswordNotChanged\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string52 = /.{0,1000}output\/WinRMMachines\.txt.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string53 = /.{0,1000}SlinkyCat\.ps1.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string54 = /.{0,1000}SlinkyCat\-main.{0,1000}/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string55 = /.{0,1000}System\.DirectoryServices\.AccountManagement\.GroupPrincipal.{0,1000}FindByIdentity.{0,1000}D/ nocase ascii wide
        // Description: This script performs a series of AD enumeration tasks
        // Reference: https://github.com/LaresLLC/SlinkyCat
        $string56 = /.{0,1000}TestWinRMMachines.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
