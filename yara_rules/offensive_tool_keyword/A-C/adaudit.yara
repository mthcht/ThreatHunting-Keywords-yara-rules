rule adaudit
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string1 = /\sADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string2 = /\/adaudit\.git/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string3 = /\/ADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string4 = /\[\!\]\sYou\shave\sDCs\swith\sRC4\sor\sDES\sallowed\sfor\sKerberos\!\!\!/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string5 = /\\accounts_passdontexpire\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string6 = /\\ADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string7 = /\\dangerousACL_Computer\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string8 = /\\dangerousACL_Groups\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string9 = /\\dcs_weak_kerberos_ciphersuite\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string10 = /\\domain_admins\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string11 = /\\enterprise_admins\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string12 = /\]\sCheck\sfor\sADCS\sVulnerabilities/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string13 = /5f871566a9113e31357e084743f12b74b7199019e66cd10847b61b5666ecf9b1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string14 = /Find\-DangerousACLPermissions/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string15 = /Get\-AccountPassDontExpire/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string16 = /Get\-ADCSVulns/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string17 = /Get\-ADUsersWithoutPreAuth/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string18 = /Get\-DCsNotOwnedByDA/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string19 = /Get\-GPOEnum/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string20 = /Get\-GPOsPerOU/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string21 = /Get\-GPOtoFile/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string22 = /Get\-GPPPassword\./ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string23 = /Get\-NTDSdit/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string24 = /Get\-PrivilegedGroupAccounts/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string25 = /Get\-PrivilegedGroupMembership/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string26 = /Kerberoast\sAttack\s\-\sServices\sConfigured\sWith\sa\sWeak\sPassword/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string27 = /phillips321\/adaudit/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string28 = /Write\-Nessus\-Finding/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string29 = /Write\-Nessus\-Footer/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string30 = /Write\-Nessus\-Header/ nocase ascii wide

    condition:
        any of them
}
