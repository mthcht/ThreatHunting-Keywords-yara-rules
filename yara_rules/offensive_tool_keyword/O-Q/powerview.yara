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
        $string2 = /\sGet\-DomainGPO\s\-Identity\s\\"\{AB306569\-220D\-43FF\-B03B\-83E8F4EF8081\}\\"/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string3 = " Invoke-ShareFinder -CheckShareAccess" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string4 = /\spowerview\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string5 = /\.powerview\.ldap_session/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string6 = /\/\.powerview\/\.powerview_history/
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string7 = /\/\.powerview\/logs/
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string8 = /\/powerview\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string9 = /\/powerview\.py\.git/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string10 = /\[Find\-DomainShare\]\sEnumerating\sserver\s/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string11 = /\\ldap_shell\.cmd/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string12 = /\\PowerView\.Log/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string13 = /\\powerview\.py/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string14 = "507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/anthonysecurity/redteam_toolkit/blob/master/References/PowerView-2.0-tricks.ps1
        $string15 = "848D3E89D46E285D5BCFA7FD13E805ABCB8BAE926F7F1B40092EA56F4A025CAA" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string16 = "8be1679cd0a2661629259d0011fe9a3bc3e7270801d97fc154577b10b85494fb" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string17 = "903fa9aeb7419d81f75d5a5a226623c5ec63a52b6da020135b864cd7d92284c9" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string18 = "9877ed9aec8766036bb9dd702e41433916a6d6c886ff55eea07fce92bcbf6b29" nocase ascii wide
        // Description: modifying existing permissions on an Active Directory object ('AdminSDHolder'). which can be used to maintain unauthorized access or escalate privileges in the targeted environment. The 'AdminSDHolder' container plays a crucial role in managing the security of protected groups in Active Directory. and modifying its permissions may lead to unintended security consequences.
        // Reference: https://github.com/zloeber/PSAD/blob/master/src/inprogress/Add-ObjectACL.ps1
        $string19 = /Add\-ObjectAcl\s\-TargetADSprefix\s\'CN\=AdminSDHolder.{0,1000}CN\=System\'\s\-PrincipalSamAccountName\s.{0,1000}\s\-Rights\sAll/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string20 = /aniqfakhrul\/powerview\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string21 = /aniqfakhrull\@gmail\.com/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string22 = "b43587da7d68a081ddc3a46993f797782e813ed07ccc5f33fe37b14a653ccfed" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string23 = "c2268ac17f1df0139ec5aa11da1ae6b8bef2ad3588f31d8e62c85a55cf85b073" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string24 = /curl\s\-L\spowerview\.sh\s/
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string25 = "d56e0de10ba38b39604171a2cfb22ff4cd6dffcd5f7646fb01a1715d39c522b6" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string26 = "d64995d25e55ebb524c83a516e8996cc3e3dd8cb03b7332f8ad95a5c775385b0" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string27 = "Export-PowerViewCSV" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string28 = "Find-GPOComputerAdmin" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string29 = "Find-InterestingDomainAcl" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string30 = "Find-InterestingDomainShareFile" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string31 = "Find-InterestingFile" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string32 = "Find-LocalAdminAccess" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string33 = /Get\-DomainComputer\s\-Ping\s\s\|\sselect\sname\,logoncount\,descreption\,operatingsystem/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string34 = "Get-DomainGPOUserLocalGroupMapping" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string35 = /Get\-DomainGroupMember\s\-Identity\s\\"Domain\sAdmins\\"\s\|/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string36 = "Get-DomainGroupMemberDeleted" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string37 = "Get-DomainSPNTicket" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string38 = "Get-DomainUser -PreauthNotRequired" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string39 = /Get\-DomainUser\s\-SPN\s\|\sselect\ssamaccountname\,serviceprincipalname/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string40 = /Get\-LastLoggedOn\s\?ComputerName\s/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string41 = "Get-LocalGroupMember -Group Administrators" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string42 = "Get-LoggedonLocal -ComputerName " nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string43 = "Get-NetLocalGroupMember" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string44 = "Get-NetLoggedon" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string45 = "Get-NetRDPSession" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string46 = "Get-RegLoggedOn" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string47 = "Get-WMIRegCachedRDPConnection" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string48 = "Get-WMIRegLastLoggedOn" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string49 = "Get-WMIRegMountedDrive" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string50 = "Invoke-EnumerateLocalAdmin" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string51 = "Invoke-Kerberoast" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string52 = "Invoke-Kerberoast" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string53 = "Invoke-RevertToSelf" nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string54 = /Invoke\-UserImpersonation\s\-Credential\s.{0,1000}\s\-Quiet/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string55 = "Invoke-UserImpersonation" nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string56 = /kerberoast\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string57 = /ldap3\.git\@powerview\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string58 = /ldapattack\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string59 = /PetitPotam\.py/ nocase ascii wide
        // Description: PowerView.py is an alternative for the awesome original PowerView.ps1
        // Reference: https://github.com/aniqfakhrul/powerview.py
        $string60 = "pip3 install powerview " nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows net commands. which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality It also implements various useful metafunctions. including some custom-written user-hunting functions which will identify where on the network specific users are logged into. It can also check which machines on the domain the current user has local administrator access on. Several functions for the enumeration and abuse of domain trusts also exist
        // Reference: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
        $string61 = /PowerView\.ps1/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string62 = /PowerView\.ShareInfo/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string63 = /PowerView\.SPNTicket/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/anthonysecurity/redteam_toolkit/blob/master/References/PowerView-2.0-tricks.ps1
        $string64 = /PowerView\-2\.0\-tricks\.ps1/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string65 = /System\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken\s\-ArgumentList\s\$UserSPN/ nocase ascii wide

    condition:
        any of them
}
