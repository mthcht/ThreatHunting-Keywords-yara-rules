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
        $string1 = /.{0,1000}\s\-command\s.{0,1000}\.exe.{0,1000}\s\-technique\sccmstp.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string2 = /.{0,1000}\s\-consoleoutput\s\-browsercredentials.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string3 = /.{0,1000}\s\-consoleoutput\s\-DomainRecon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string4 = /.{0,1000}\s\-consoleoutput\s\-Localrecon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string5 = /.{0,1000}\/LocalPrivEsc\/.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string6 = /.{0,1000}\/WinPwn.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string7 = /.{0,1000}\/WinPwn\.git.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string8 = /.{0,1000}\/WinPwn_Repo.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string9 = /.{0,1000}\\DomainRecon\\.{0,1000}\.txt/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string10 = /.{0,1000}\\LocalPrivEsc\\.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string11 = /.{0,1000}\\Passwordfiles\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string12 = /.{0,1000}\\Seatbelt\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string13 = /.{0,1000}\\SQLInfoDumps.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string14 = /.{0,1000}\\temp\\dump\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string15 = /.{0,1000}\\temp\\pwned\.trx.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string16 = /.{0,1000}\\Users_Nochangedpassword\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string17 = /.{0,1000}\\WritebleRegistryKeys\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string18 = /.{0,1000}ADCS_Maybe_ESC8_HTTPS_Vulnerable\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string19 = /.{0,1000}AllowDelegationUsers\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string20 = /.{0,1000}AllowDelegationUsers_samaccountnames_only\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string21 = /.{0,1000}asreproast\s\/.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string22 = /.{0,1000}ASreproasting\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string23 = /.{0,1000}breviaries\s\-Properties\sDnsHostName.{0,1000}ms\-Mcs\-AdmPwd.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string24 = /.{0,1000}\-command\s.{0,1000}\.exe.{0,1000}\s\-technique\sccmstp.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string25 = /.{0,1000}\-consoleoutput\s\-DomainRecon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string26 = /.{0,1000}\-consoleoutput\s\-Localrecon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string27 = /.{0,1000}decryptteamviewer.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string28 = /.{0,1000}Domainpassspray.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string29 = /.{0,1000}DomainRecon\\ADCSServer\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string30 = /.{0,1000}DomainRecon\\DC\-IPs\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string31 = /.{0,1000}DomainRecon\\ExploitableSystems\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string32 = /.{0,1000}DomainRecon\\OxidBindings\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string33 = /.{0,1000}DomainRecon\\Windows_Servers\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string34 = /.{0,1000}dumplsass.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string35 = /.{0,1000}Enabled_Users1\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string36 = /.{0,1000}Generalrecon\s\-noninteractive.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string37 = /.{0,1000}Get_WinPwn_Repo\.sh.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string38 = /.{0,1000}GPO\-RemoteAccess\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string39 = /.{0,1000}GPP_Passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string40 = /.{0,1000}Invoke\-ADCSTemplateRecon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string41 = /.{0,1000}Invoke\-BlockETW.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string42 = /.{0,1000}Invoke\-Certify.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string43 = /.{0,1000}Invoke\-DomainPasswordSpray.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string44 = /.{0,1000}Invoke\-Get\-RBCD\-Threaded.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string45 = /.{0,1000}Invoke\-Grouper2.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string46 = /.{0,1000}Invoke\-Grouper3.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string47 = /.{0,1000}Invoke\-HandleKatz.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string48 = /.{0,1000}Invoke\-Handlekatz.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string49 = /.{0,1000}Invoke\-Internalmonologue.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string50 = /.{0,1000}Invoke\-Inveigh.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string51 = /.{0,1000}Invoke\-InveighRelay.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string52 = /.{0,1000}Invoke\-JuicyPotato.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string53 = /.{0,1000}Invoke\-LdapSignCheck.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string54 = /.{0,1000}Invoke\-MalSCCM.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string55 = /.{0,1000}Invoke\-MS16.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string56 = /.{0,1000}Invoke\-NanoDump.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string57 = /.{0,1000}Invoke\-Nightmare.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string58 = /.{0,1000}Invoke\-Oxidresolver.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string59 = /.{0,1000}Invoke\-OxidResolver.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string60 = /.{0,1000}Invoke\-PowerDump.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string61 = /.{0,1000}Invoke\-Privesc.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string62 = /.{0,1000}Invoke\-RBDC.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string63 = /.{0,1000}Invoke\-RBDC\-over\-DAVRPC.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string64 = /.{0,1000}Invoke\-Reg1c1de.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string65 = /.{0,1000}Invoke\-Rubeus.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string66 = /.{0,1000}Invoke\-S3ssionGoph3r.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string67 = /.{0,1000}Invoke\-Seatbelt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string68 = /.{0,1000}Invoke\-SharpCloud.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string69 = /.{0,1000}Invoke\-Sharpcradle.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string70 = /.{0,1000}Invoke\-SharpGPO.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string71 = /.{0,1000}Invoke\-Sharphound.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string72 = /.{0,1000}Invoke\-Sharphound4.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string73 = /.{0,1000}Invoke\-SharpImpersonation.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string74 = /.{0,1000}Invoke\-SharpLdapRelayScan.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string75 = /.{0,1000}Invoke\-SharpPrinter.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string76 = /.{0,1000}Invoke\-SharpSCCM.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string77 = /.{0,1000}Invoke\-SharpUp.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string78 = /.{0,1000}Invoke\-Sharpweb.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string79 = /.{0,1000}Invoke\-SMBClient.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string80 = /.{0,1000}Invoke\-SMBEnum.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string81 = /.{0,1000}Invoke\-SMBExec.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string82 = /.{0,1000}Invoke\-SMBNegotiate\s\-ComputerName\slocalhost.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string83 = /.{0,1000}Invoke\-SMBNegotiate.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string84 = /.{0,1000}Invoke\-Snaffler.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string85 = /.{0,1000}Invoke\-SpoolSample.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string86 = /.{0,1000}Invoke\-SprayEmptyPassword.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string87 = /.{0,1000}Invoke\-SQLAudit.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string88 = /.{0,1000}Invoke\-SQLDumpInfo.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string89 = /.{0,1000}Invoke\-SQLUncPathInjection.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string90 = /.{0,1000}Invoke\-TheKatz.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string91 = /.{0,1000}Invoke\-Vulmap.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string92 = /.{0,1000}Invoke\-VulnerableADCSTemplates.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string93 = /.{0,1000}Invoke\-watson.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string94 = /.{0,1000}Invoke\-WCMDump.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string95 = /.{0,1000}Invoke\-winPEAS.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string96 = /.{0,1000}Invoke\-Zerologon.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string97 = /.{0,1000}itm4nprivesc.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string98 = /.{0,1000}kerberoast\s\/.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string99 = /.{0,1000}Kittielocal\s\-.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string100 = /.{0,1000}LapsAllowedAdminGroups\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string101 = /.{0,1000}LapsPasswords\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string102 = /.{0,1000}Lazagne.{0,1000}Passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string103 = /.{0,1000}localreconmodules.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string104 = /.{0,1000}lsassdumps.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string105 = /.{0,1000}MS\-RPNVulnerableDC\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string106 = /.{0,1000}NanoDumpChoose.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string107 = /.{0,1000}nc\.exe\s127\.0\.0\.1\s4444.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string108 = /.{0,1000}obfuskittiedump.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string109 = /.{0,1000}Offline_WinPwn\.ps1.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string110 = /.{0,1000}passhunt\.exe.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string111 = /.{0,1000}password\|passwort\|passwd\|.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string112 = /.{0,1000}Passwords_in_description\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string113 = /.{0,1000}pwned_x64\/notepad\.exe.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string114 = /.{0,1000}Pwned\-creds_Domainpasswordspray\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string115 = /.{0,1000}RBCD_Petitpotam_VulnerableServers\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string116 = /.{0,1000}RottenPotatoVulnerable\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string117 = /.{0,1000}SCCM_DLLSiteloading\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string118 = /.{0,1000}Sensitivelocalfiles\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string119 = /.{0,1000}shareenumeration.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string120 = /.{0,1000}SharpLdapRelayScan.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string121 = /.{0,1000}Sherlock_Vulns\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string122 = /.{0,1000}SQLServer_Accessible_PotentialSensitiveData\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string123 = /.{0,1000}SQLServer_DefaultLogin\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string124 = /.{0,1000}System32fileWritePermissions\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string125 = /.{0,1000}temp\\stager\.exe.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string126 = /.{0,1000}UACBypass\s\-.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string127 = /.{0,1000}uacm4gic.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string128 = /.{0,1000}Unconstrained_Delegation_Systems\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string129 = /.{0,1000}UsernameAsPasswordCreds\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string130 = /.{0,1000}WCMCredentials\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string131 = /.{0,1000}whoami\s\/priv\s\|\sfindstr\s\/i\s\/C:.{0,1000}SeImpersonatePrivilege.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string132 = /.{0,1000}WinCreds\.exe.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string133 = /.{0,1000}winPEAS\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string134 = /.{0,1000}WinPwn\s\-.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string135 = /.{0,1000}WinPwn\.exe.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string136 = /.{0,1000}WinPwn\.ps1.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string137 = /.{0,1000}WriteDLLPermission\.txt.{0,1000}/ nocase ascii wide
        // Description: Automation for internal Windows Penetrationtest AD-Security
        // Reference: https://github.com/S3cur3Th1sSh1t/WinPwn
        $string138 = /.{0,1000}\-\-ZipFileName\s\$TrustedDomain\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
