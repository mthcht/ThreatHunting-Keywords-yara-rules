rule WinPwn
{
    meta:
        description = "Detection patterns for the tool 'WinPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string1 = /\s\-command\s.{0,1000}\.exe.{0,1000}\s\-technique\sccmstp/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string2 = " -consoleoutput -browsercredentials" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string3 = " -consoleoutput -DomainRecon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string4 = " -consoleoutput -Localrecon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string5 = "/LocalPrivEsc/" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string6 = "/WinPwn" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string7 = /\/WinPwn\.git/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string8 = "/WinPwn_Repo" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string9 = /\\DomainRecon\\.{0,1000}\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string10 = /\\LocalPrivEsc\\/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string11 = /\\Passwordfiles\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string12 = /\\Seatbelt\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string13 = /\\SQLInfoDumps/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string14 = /\\temp\\dump\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string15 = /\\temp\\pwned\.trx/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string16 = /\\Users_Nochangedpassword\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string17 = /\\WritebleRegistryKeys\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string18 = /ADCS_Maybe_ESC8_HTTPS_Vulnerable\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string19 = /AllowDelegationUsers\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string20 = /AllowDelegationUsers_samaccountnames_only\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string21 = "asreproast /" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string22 = /ASreproasting\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string23 = /breviaries\s\-Properties\sDnsHostName.{0,1000}ms\-Mcs\-AdmPwd/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string24 = /\-command\s.{0,1000}\.exe.{0,1000}\s\-technique\sccmstp/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string25 = "-consoleoutput -DomainRecon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string26 = "-consoleoutput -Localrecon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string27 = "decryptteamviewer" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string28 = "Discover-PSInterestingServices" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string29 = "Domainpassspray" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string30 = /DomainRecon\\ADCSServer\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string31 = /DomainRecon\\DC\-IPs\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string32 = /DomainRecon\\ExploitableSystems\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string33 = /DomainRecon\\OxidBindings\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string34 = /DomainRecon\\Windows_Servers\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string35 = "dumplsass" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string36 = /Enabled_Users1\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string37 = "Generalrecon -noninteractive" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string38 = /Get_WinPwn_Repo\.sh/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string39 = /GPO\-RemoteAccess\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string40 = /GPP_Passwords\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string41 = "Invoke-ADCSTemplateRecon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string42 = "Invoke-BlockETW" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string43 = "Invoke-Certify" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string44 = "Invoke-DomainPasswordSpray" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string45 = "Invoke-Get-RBCD-Threaded" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string46 = "Invoke-Grouper2" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string47 = "Invoke-Grouper3" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string48 = "Invoke-HandleKatz" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string49 = "Invoke-Handlekatz" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string50 = "Invoke-Internalmonologue" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string51 = "Invoke-Inveigh" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string52 = "Invoke-InveighRelay" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string53 = "Invoke-JuicyPotato" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string54 = "Invoke-LdapSignCheck" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string55 = "Invoke-MalSCCM" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string56 = "Invoke-MS16" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string57 = "Invoke-NanoDump" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string58 = "Invoke-Nightmare" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string59 = "Invoke-Oxidresolver" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string60 = "Invoke-OxidResolver" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string61 = "Invoke-PowerDump" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string62 = "Invoke-Privesc" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string63 = "Invoke-RBDC" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string64 = "Invoke-RBDC-over-DAVRPC" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string65 = "Invoke-Reg1c1de" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string66 = "Invoke-Rubeus" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string67 = "Invoke-S3ssionGoph3r" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string68 = "Invoke-Seatbelt" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string69 = "Invoke-SharpCloud" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string70 = "Invoke-Sharpcradle" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string71 = "Invoke-SharpGPO" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string72 = "Invoke-Sharphound" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string73 = "Invoke-Sharphound4" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string74 = "Invoke-SharpImpersonation" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string75 = "Invoke-SharpLdapRelayScan" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string76 = "Invoke-SharpPrinter" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string77 = "Invoke-SharpSCCM" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string78 = "Invoke-SharpUp" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string79 = "Invoke-Sharpweb" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string80 = "Invoke-SMBClient" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string81 = "Invoke-SMBEnum" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string82 = "Invoke-SMBExec" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string83 = "Invoke-SMBNegotiate -ComputerName localhost" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string84 = "Invoke-SMBNegotiate" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string85 = "Invoke-Snaffler" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string86 = "Invoke-SpoolSample" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string87 = "Invoke-SprayEmptyPassword" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string88 = "Invoke-SQLAudit" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string89 = "Invoke-SQLDumpInfo" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string90 = "Invoke-SQLUncPathInjection" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string91 = "Invoke-TheKatz" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string92 = "Invoke-Vulmap" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string93 = "Invoke-VulnerableADCSTemplates" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string94 = "Invoke-watson" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string95 = "Invoke-WCMDump" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string96 = "Invoke-winPEAS" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string97 = "Invoke-Zerologon" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string98 = "itm4nprivesc" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string99 = "kerberoast /" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string100 = "Kittielocal -" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string101 = /LapsAllowedAdminGroups\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string102 = /LapsPasswords\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string103 = /Lazagne.{0,1000}Passwords\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string104 = "localreconmodules" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string105 = "lsassdumps" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string106 = /MS\-RPNVulnerableDC\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string107 = "NanoDumpChoose" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string108 = /nc\.exe\s127\.0\.0\.1\s4444/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string109 = "obfuskittiedump" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string110 = /Offline_WinPwn\.ps1/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string111 = /passhunt\.exe/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string112 = /password\|passwort\|passwd\|/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string113 = /Passwords_in_description\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string114 = /pwned_x64\/notepad\.exe/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string115 = /Pwned\-creds_Domainpasswordspray\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string116 = /RBCD_Petitpotam_VulnerableServers\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string117 = /RottenPotatoVulnerable\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string118 = /SCCM_DLLSiteloading\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string119 = /Sensitivelocalfiles\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string120 = "shareenumeration" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string121 = "SharpLdapRelayScan" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string122 = /Sherlock_Vulns\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string123 = /SQLServer_Accessible_PotentialSensitiveData\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string124 = /SQLServer_DefaultLogin\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string125 = /System32fileWritePermissions\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string126 = /temp\\stager\.exe/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string127 = "UACBypass -" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string128 = "uacm4gic" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string129 = /Unconstrained_Delegation_Systems\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string130 = /UsernameAsPasswordCreds\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string131 = /WCMCredentials\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string132 = /whoami\s\/priv\s\|\sfindstr\s\/i\s\/C\:.{0,1000}SeImpersonatePrivilege/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string133 = /WinCreds\.exe/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string134 = /winPEAS\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string135 = "WinPwn -" nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string136 = /WinPwn\.exe/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string137 = /WinPwn\.ps1/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string138 = /WriteDLLPermission\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string139 = /\-\-ZipFileName\s\$TrustedDomain\.zip/ nocase ascii wide

    condition:
        any of them
}
