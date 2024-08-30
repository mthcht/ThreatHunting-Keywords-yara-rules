rule powerview
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string1 = /\sGet\-DomainController\s\|\sselect\sName\,OSversion\,IPAddress\s\|fl/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string2 = /\sGet\-DomainGPO\s\-Identity\s\"\{AB306569\-220D\-43FF\-B03B\-83E8F4EF8081\}\"/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string3 = /\sInvoke\-ShareFinder\s\-CheckShareAccess/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string4 = /\[Find\-DomainShare\]\sEnumerating\sserver\s/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string5 = /\\PowerView\.Log/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string6 = /507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string7 = /507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87/ nocase ascii wide
        // Description: modifying existing permissions on an Active Directory object ('AdminSDHolder'). which can be used to maintain unauthorized access or escalate privileges in the targeted environment. The 'AdminSDHolder' container plays a crucial role in managing the security of protected groups in Active Directory. and modifying its permissions may lead to unintended security consequences.
        // Reference: https://github.com/zloeber/PSAD/blob/master/src/inprogress/Add-ObjectACL.ps1
        $string8 = /Add\-ObjectAcl\s\-TargetADSprefix\s\'CN\=AdminSDHolder.{0,1000}CN\=System\'\s\-PrincipalSamAccountName\s.{0,1000}\s\-Rights\sAll/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string9 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string10 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string11 = /Find\-GPOComputerAdmin/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string12 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string13 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string14 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string15 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string16 = /Find\-InterestingFile/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string17 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string18 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string19 = /Get\-DomainComputer\s\-Ping\s\s\|\sselect\sname\,logoncount\,descreption\,operatingsystem/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string20 = /Get\-DomainGPOUserLocalGroupMapping/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string21 = /Get\-DomainGroupMember\s\-Identity\s\"Domain\sAdmins\"\s\|/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string22 = /Get\-DomainGroupMemberDeleted/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string23 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string24 = /Get\-DomainUser\s\-PreauthNotRequired/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string25 = /Get\-DomainUser\s\-SPN\s\|\sselect\ssamaccountname\,serviceprincipalname/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string26 = /Get\-LastLoggedOn\s\?ComputerName\s/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string27 = /Get\-LocalGroupMember\s\-Group\sAdministrators/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string28 = /Get\-LoggedonLocal\s\-ComputerName\s/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string29 = /Get\-NetLocalGroupMember/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string30 = /Get\-NetLoggedon/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string31 = /Get\-NetRDPSession/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string32 = /Get\-RegLoggedOn/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string33 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string34 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string35 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string36 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string37 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string38 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string39 = /Get\-WMIRegMountedDrive/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string40 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string41 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string42 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string43 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string44 = /Invoke\-RevertToSelf/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string45 = /Invoke\-RevertToSelf/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string46 = /Invoke\-UserImpersonation\s\-Credential\s.{0,1000}\s\-Quiet/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string47 = /Invoke\-UserImpersonation/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows net commands. which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality It also implements various useful metafunctions. including some custom-written user-hunting functions which will identify where on the network specific users are logged into. It can also check which machines on the domain the current user has local administrator access on. Several functions for the enumeration and abuse of domain trusts also exist
        // Reference: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
        $string48 = /PowerView\.ps1/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string49 = /PowerView\.ShareInfo/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string50 = /PowerView\.SPNTicket/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string51 = /System\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken\s\-ArgumentList\s\$UserSPN/ nocase ascii wide

    condition:
        any of them
}
