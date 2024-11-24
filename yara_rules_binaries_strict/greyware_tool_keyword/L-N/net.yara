rule net
{
    meta:
        description = "Detection patterns for the tool 'net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerate local accounts
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1 = /\\net\.exe\\"\saccounts/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string2 = /\\net\.exe.{0,100}\slocalgroup\sadmin/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3 = /\\net\.exe.{0,100}\ssessions/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4 = /\\net\.exe.{0,100}\sview\s.{0,100}\/domain/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5 = /\\net1\ssessions/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string6 = "net  group \"domain admins\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string7 = "net  group \"Domain Computers\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string8 = "net  group \"domain computers\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string9 = "net  group \"enterprise admins\" /domain" nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string10 = "net  group \"ESX Admins\" /domain /add" nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string11 = "net  group \"ESX Admins\"" nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string12 = "net  user admin P@ssw0rd!" nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string13 = /net\s\.exe.{0,100}\sgroup\s\\"ESX\sAdmins\\"/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string14 = "net group \"Domain Admins\" /domain" nocase ascii wide
        // Description: List PCs connected to the domain
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string15 = "net group \"domain computers\" /domain" nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16 = /net\sgroup\s.{0,100}Account\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /net\sgroup\s.{0,100}Backup\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string18 = /net\sgroup\s.{0,100}Domain\sComputers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string19 = /net\sgroup\s.{0,100}Domain\sControllers.{0,100}\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string20 = /net\sgroup\s.{0,100}Domain\sControllers.{0,100}\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string21 = /net\sgroup\s.{0,100}Enterprise\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string22 = /net\sgroup\s.{0,100}Exchange\sTrusted\sSubsystem.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string23 = /net\sgroup\s.{0,100}Microsoft\sExchange\sServers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string24 = /net\sgroup\s.{0,100}Print\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25 = /net\sgroup\s.{0,100}Schema\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26 = /net\sgroup\s.{0,100}Server\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string27 = /net\sgroup\s\/domain\s.{0,100}Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string28 = "net group administrators /domain" nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string29 = /net\slocalgroup\s\\"Remote\sDesktop\sUsers\\"\s.{0,100}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string30 = /net\slocalgroup\s.{0,100}Backup\sOperators/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string31 = "net localgroup admin" nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string32 = /net\sshare\sc\=c\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string33 = /net\sshare\sd\=d\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string34 = /net\sshare\se\=e\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string35 = /net\sshare\se\=e\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string36 = /net\sshare\sf\=f\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string37 = /net\sshare\sg\=g\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string38 = /net\sshare\sh\=h\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string39 = /net\sshare\si\=i\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string40 = /net\sshare\sj\=j\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: create shared folders for various drive letters
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string41 = /net\sshare\sk\=k\:\\\s\/GRANT\:Everyone\,FULL/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string42 = /net\sstop\s\\"\.NET\sRuntime\sOptimization\sService\\"/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string43 = /net\sstop\s\\"IBM\sDomino\sDiagnostics\s\(CProgramFilesIBMDomino\)\\"/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string44 = /net\sstop\s\\"IBM\sDomino\sServer\s\(CProgramFilesIBMDominodata\)\\"/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string45 = "net stop \"Simply Accounting Database Connection Manager\"" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string46 = "net stop \"Sophos " nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string47 = "net stop \"SQL Backups\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string48 = "net stop \"SQLsafe Backup Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string49 = /net\sstop\s\\"storagecraft\simagemanager.{0,100}\\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string50 = "net stop \"Symantec System Recovery\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string51 = "net stop \"Veeam Backup Catalog Data Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string52 = "net stop \"Zoolz 2 Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string53 = "net stop acronisagent" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string54 = "net stop AcronisAgent" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string55 = "net stop acrsch2svc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string56 = "net stop AcrSch2Svc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string57 = "net stop agntsvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string58 = "net stop Antivirus" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string59 = "net stop ARSM /y" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string60 = "net stop arsm" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string61 = "net stop AVP" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string62 = "net stop backp" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string63 = "net stop backup" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string64 = "net stop BackupExec" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string65 = "net stop BackupExecAgent" nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string66 = "net stop badrv" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string67 = "net stop bedbg /y" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string68 = "net stop cbservi" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string69 = "net stop cbvscserv" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string70 = "net stop DCAgent" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string71 = "net stop dnscache" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string72 = "net stop DPS" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string73 = "net stop EhttpSrv" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string74 = "net stop ekrn" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string75 = /net\sstop\sEPSecurityService.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string76 = /net\sstop\sEPUpdateService.{0,100}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string77 = "net stop EsgShKernel" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string78 = "net stop ESHASRV" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string79 = "net stop FA_Scheduler" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string80 = "net stop firebirdguardiandefaultinstance" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string81 = "net stop gupdatem" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string82 = "net stop ibmiasrw" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string83 = "net stop IISADMIN" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string84 = "net stop IISADMIN" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string85 = "net stop IMAP4Svc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string86 = "net stop KAVFS" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string87 = "net stop KAVFSGT" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string88 = "net stop kavfsslp" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string89 = "net stop klnagent" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string90 = "net stop macmnsvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string91 = "net stop masvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string92 = "net stop MBAMService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string93 = /net\sstop\sMBEndpointAgent.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string94 = /net\sstop\sMcAfeeEngineService.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string95 = "net stop McAfeeFramework" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string96 = "net stop McAfeeFrameworkMcAfeeFramework" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string97 = "net stop McShield" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string98 = "net stop mfefire" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string99 = "net stop mfemms" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string100 = "net stop mfevtp" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string101 = "net stop mozyprobackup" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string102 = "net stop mr2kserv" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string103 = "net stop MsDtsServer" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string104 = "net stop MsDtsServer100" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string105 = "net stop MsDtsServer110" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string106 = "net stop MSExchangeADTopology" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string107 = "net stop MSExchangeFBA" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string108 = "net stop MSExchangeIS" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string109 = "net stop MSExchangeSA" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string110 = /net\sstop\smsftesql\$PROD/ nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string111 = "net stop msiserver" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string112 = /net\sstop\sMSOLAP\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string113 = /net\sstop\sMSOLAP\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string114 = /net\sstop\sMSOLAP\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string115 = /net\sstop\sMSOLAP\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string116 = /net\sstop\sMSSQL\$BKUPEXEC/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string117 = /net\sstop\sMSSQL\$CONTOSO1/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string118 = /net\sstop\sMSSQL\$ECWDB2/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string119 = /net\sstop\sMSSQL\$ISARS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string120 = /net\sstop\sMSSQL\$MSFW/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string121 = /net\sstop\sMSSQL\$PRACTICEMGT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string122 = /net\sstop\sMSSQL\$PRACTTICEBGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string123 = /net\sstop\sMSSQL\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string124 = /net\sstop\sMSSQL\$PROFXENGAGEMENT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string125 = /net\sstop\sMSSQL\$SBSMONITORING/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string126 = /net\sstop\sMSSQL\$SHAREPOINT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string127 = /net\sstop\sMSSQL\$SOPHOS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string128 = /net\sstop\sMSSQL\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string129 = /net\sstop\sMSSQL\$SQLEXPRESS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string130 = /net\sstop\sMSSQL\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string131 = /net\sstop\sMSSQL\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string132 = /net\sstop\sMSSQL\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string133 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string134 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string135 = "net stop MSSQLServerADHelper100" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string136 = "net stop MSSQLServerADHelper100" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string137 = "net stop OfficeClickToRun" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string138 = "net stop PcaSvc" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string139 = "net stop QBCFMonitorService" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string140 = "net stop QBPOSDBServiceV12" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string141 = "net stop QBVSS" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string142 = "net stop QuickBooksDB1" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string143 = "net stop QuickBooksDB2" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string144 = "net stop QuickBooksDB3" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string145 = "net stop QuickBooksDB4" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string146 = "net stop QuickBooksDB5" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string147 = /net\sstop\sReportServer\$ISARS/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string148 = "net stop sacsvr" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string149 = "net stop SAVAdminService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string150 = "net stop SAVService" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string151 = "net stop sedsvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string152 = "net stop shadowprotectsvc" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string153 = "net stop ShadowProtectSvc" nocase ascii wide
        // Description: stopping shared access
        // Reference: N/A
        $string154 = "net stop sharedaccess" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string155 = "net stop ShMonitor" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string156 = "net stop Smcinst" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string157 = "net stop SmcService" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string158 = "net stop sms_site_sql_backup" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string159 = /net\sstop\sSntpService.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string160 = "net stop sophossps" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string161 = "net stop SPAdminV4" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string162 = "net stop sppsvc" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string163 = "net stop SPSearch4" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string164 = "net stop SPTimerV4" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string165 = "net stop SPTraceV4" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string166 = "net stop SPUserCodeV4" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string167 = "net stop SPWriterV4" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string168 = "net stop spxservice" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string169 = "net stop sqbcoreservice" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string170 = /net\sstop\sSQLAgent\$ISARS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string171 = /net\sstop\sSQLAgent\$MSFW/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string172 = /net\sstop\sSQLAgent\$SOPH/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string173 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string174 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string175 = "net stop SQLBrowser" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string176 = "net stop SQLWriter" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string177 = "net stop stc_endpt_svc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string178 = "net stop stop SepMasterService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string179 = "net stop svcGenericHost" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string180 = "net stop swi_filter" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string181 = "net stop swi_service" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string182 = "net stop swi_update" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string183 = "net stop swi_update_64" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string184 = "net stop SysMain" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string185 = "net stop TmCCSF" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string186 = "net stop tmlisten" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string187 = "net stop TrueKey" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string188 = /net\sstop\sTrueKeyScheduler.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string189 = "net stop TrueKeyServiceHel" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string190 = "net stop TrustedInstaller" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string191 = /net\sstop\svapiendpoint.{0,100}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string192 = "net stop VeeamBackupSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string193 = "net stop VeeamBrokerSvc " nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string194 = "net stop VeeamCatalogSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string195 = "net stop VeeamCloudSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string196 = "net stop VeeamDeploymentService" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string197 = "net stop VeeamDeploySvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string198 = /net\sstop\sVeeamDeploySvc.{0,100}\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string199 = "net stop VeeamEnterpriseManagerSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string200 = "net stop VeeamHvIntegrationSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string201 = "net stop VeeamMountSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string202 = "net stop VeeamNFSSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string203 = "net stop VeeamRESTSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string204 = "net stop VeeamTransportSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string205 = "net stop vsnapvss" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string206 = "net stop vssvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string207 = "net stop wbengine" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string208 = "net stop wbengine" nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string209 = "net stop WinDefend" nocase ascii wide
        // Description: stopping AV services
        // Reference: N/A
        $string210 = "net stop WinDefend" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string211 = "net stop WRSVC" nocase ascii wide
        // Description: connect to the "IPC$" share on a remote system often for lateral movement or remote administration purposes
        // Reference: N/A
        $string212 = /net\suse\s\\\\.{0,100}\\IPC\$\s\/user\:/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string213 = /net\suser\s.{0,100}\$.{0,100}\s\// nocase ascii wide
        // Description: Create list of domain users
        // Reference: N/A
        $string214 = "net user /domain >" nocase ascii wide
        // Description: activate the guest account in Windows
        // Reference: N/A
        $string215 = "NET USER GUEST /ACTIVE:YES" nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string216 = "net view /all /domain" nocase ascii wide
        // Description: display all domain names on the network
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string217 = "net view /domain" nocase ascii wide
        // Description: retrieves a list of shared resources on a remote machine
        // Reference: N/A
        $string218 = /net\sview\s\\\\.{0,100}\s\/all/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string219 = /net.{0,100}\sgroup\sAdministrator.{0,100}\s\/add\s\/domain/ nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string220 = /net\.exe\slocalgroup\s\\"Remote\sDesktop\sUsers\\"\s.{0,100}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string221 = /net\.exe\slocalgroup\s.{0,100}Backup\sOperators/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string222 = /net\.exe\\"\slocalgroup\s.{0,100}Backup\sOperators/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string223 = /net\.exe.{0,100}\sgroup\s.{0,100}Account\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string224 = /net\.exe.{0,100}\sgroup\s.{0,100}Backup\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string225 = /net\.exe.{0,100}\sgroup\s.{0,100}Domain\sComputers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string226 = /net\.exe.{0,100}\sgroup\s.{0,100}Domain\sControllers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string227 = /net\.exe.{0,100}\sgroup\s.{0,100}Enterprise\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string228 = /net\.exe.{0,100}\sgroup\s.{0,100}Exchange\sTrusted\sSubsystem.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string229 = /net\.exe.{0,100}\sgroup\s.{0,100}Microsoft\sExchange\sServers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string230 = /net\.exe.{0,100}\sgroup\s.{0,100}Print\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string231 = /net\.exe.{0,100}\sgroup\s.{0,100}Schema\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string232 = /net\.exe.{0,100}\sgroup\s.{0,100}Server\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string233 = "net1  group \"domain admins\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string234 = "net1  group \"Domain Computers\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string235 = "net1  group \"domain computers\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string236 = "net1  group \"enterprise admins\" /domain" nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string237 = "net1 group \"Domain Admins\" /domain" nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string238 = /net1\sgroup\s.{0,100}Account\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string239 = /net1\sgroup\s.{0,100}Backup\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string240 = /net1\sgroup\s.{0,100}Domain\sComputers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string241 = /net1\sgroup\s.{0,100}Domain\sControllers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string242 = /net1\sgroup\s.{0,100}Enterprise\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string243 = /net1\sgroup\s.{0,100}Exchange\sTrusted\sSubsystem.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string244 = /net1\sgroup\s.{0,100}Microsoft\sExchange\sServers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string245 = /net1\sgroup\s.{0,100}Print\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string246 = /net1\sgroup\s.{0,100}Schema\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string247 = /net1\sgroup\s.{0,100}Server\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string248 = /net1\slocalgroup\s\\"Remote\sDesktop\sUsers\\"\s.{0,100}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string249 = /net1\slocalgroup\s.{0,100}Backup\sOperators/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string250 = "net1 localgroup admin" nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string251 = "net1 stop badrv" nocase ascii wide
        // Description: observed used by lslsass sample (dump active logon session password hashes from the lsass process (old tool for vista and older))
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string252 = "net1 stop gupdatem" nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string253 = /net1\.exe.{0,100}\sgroup\s.{0,100}Account\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string254 = /net1\.exe.{0,100}\sgroup\s.{0,100}Backup\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string255 = /net1\.exe.{0,100}\sgroup\s.{0,100}Domain\sComputers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string256 = /net1\.exe.{0,100}\sgroup\s.{0,100}Domain\sControllers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string257 = /net1\.exe.{0,100}\sgroup\s.{0,100}Enterprise\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string258 = /net1\.exe.{0,100}\sgroup\s.{0,100}Exchange\sTrusted\sSubsystem.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string259 = /net1\.exe.{0,100}\sgroup\s.{0,100}Microsoft\sExchange\sServers.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string260 = /net1\.exe.{0,100}\sgroup\s.{0,100}Print\sOperators.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string261 = /net1\.exe.{0,100}\sgroup\s.{0,100}Schema\sAdmins.{0,100}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string262 = /net1\.exe.{0,100}\sgroup\s.{0,100}Server\sOperators.{0,100}\s\/domain/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
