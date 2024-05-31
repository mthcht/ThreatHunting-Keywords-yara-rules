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
        $string1 = /507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87/ nocase ascii wide
        // Description: modifying existing permissions on an Active Directory object ('AdminSDHolder'). which can be used to maintain unauthorized access or escalate privileges in the targeted environment. The 'AdminSDHolder' container plays a crucial role in managing the security of protected groups in Active Directory. and modifying its permissions may lead to unintended security consequences.
        // Reference: https://github.com/zloeber/PSAD/blob/master/src/inprogress/Add-ObjectACL.ps1
        $string2 = /Add\-ObjectAcl\s\-TargetADSprefix\s\'CN\=AdminSDHolder.{0,1000}CN\=System\'\s\-PrincipalSamAccountName\s.{0,1000}\s\-Rights\sAll/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string3 = /Get\-NetLocalGroupMember/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string4 = /Get\-NetLoggedon/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string5 = /Get\-NetRDPSession/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string6 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string7 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string8 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows net commands. which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality It also implements various useful metafunctions. including some custom-written user-hunting functions which will identify where on the network specific users are logged into. It can also check which machines on the domain the current user has local administrator access on. Several functions for the enumeration and abuse of domain trusts also exist
        // Reference: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
        $string9 = /PowerView\.ps1/ nocase ascii wide

    condition:
        any of them
}
