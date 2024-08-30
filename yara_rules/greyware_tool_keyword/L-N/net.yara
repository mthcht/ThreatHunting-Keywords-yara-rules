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
        $string1 = /\\net\.exe\"\saccounts/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string2 = /\\net\.exe.{0,1000}\slocalgroup\sadmin/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3 = /\\net\.exe.{0,1000}\ssessions/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4 = /\\net\.exe.{0,1000}\sview\s.{0,1000}\/domain/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5 = /\\net1\ssessions/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string6 = /net\s\sgroup\s\"domain\sadmins\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string7 = /net\s\sgroup\s\"Domain\sComputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string8 = /net\s\sgroup\s\"domain\scomputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string9 = /net\s\sgroup\s\"enterprise\sadmins\"\s\/domain/ nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string10 = /net\s\sgroup\s\"ESX\sAdmins\"\s\/domain\s\/add/ nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string11 = /net\s\sgroup\s\"ESX\sAdmins\"/ nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string12 = /net\s\suser\sadmin\sP\@ssw0rd\!/ nocase ascii wide
        // Description: potential CVE-2024-37085 exploitation
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
        $string13 = /net\s\.exe.{0,1000}\sgroup\s\"ESX\sAdmins\"/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string14 = /net\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: List PCs connected to the domain
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string15 = /net\sgroup\s\"domain\scomputers\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16 = /net\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /net\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string18 = /net\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string19 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string20 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string21 = /net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string22 = /net\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string23 = /net\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string24 = /net\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25 = /net\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26 = /net\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string27 = /net\sgroup\s\/domain\s.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string28 = /net\sgroup\sadministrators\s\/domain/ nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string29 = /net\slocalgroup\s\"Remote\sDesktop\sUsers\"\s.{0,1000}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string30 = /net\slocalgroup\s.{0,1000}Backup\sOperators/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string31 = /net\slocalgroup\sadmin/ nocase ascii wide
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
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string42 = /net\sstop\s\"IBM\sDomino\sDiagnostics\s\(CProgramFilesIBMDomino\)\"/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string43 = /net\sstop\s\"IBM\sDomino\sServer\s\(CProgramFilesIBMDominodata\)\"/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string44 = /net\sstop\s\"Simply\sAccounting\sDatabase\sConnection\sManager\"/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string45 = /net\sstop\s\"Sophos\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string46 = /net\sstop\s\"SQL\sBackups\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string47 = /net\sstop\s\"SQLsafe\sBackup\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string48 = /net\sstop\s\"storagecraft\simagemanager.{0,1000}\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string49 = /net\sstop\s\"Symantec\sSystem\sRecovery\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string50 = /net\sstop\s\"Veeam\sBackup\sCatalog\sData\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string51 = /net\sstop\s\"Zoolz\s2\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string52 = /net\sstop\sacronisagent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string53 = /net\sstop\sAcronisAgent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string54 = /net\sstop\sacrsch2svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string55 = /net\sstop\sAcrSch2Svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string56 = /net\sstop\sagntsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string57 = /net\sstop\sAntivirus/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string58 = /net\sstop\sARSM\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string59 = /net\sstop\sarsm/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string60 = /net\sstop\sAVP/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string61 = /net\sstop\sbackp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string62 = /net\sstop\sbackup/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string63 = /net\sstop\sBackupExec/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string64 = /net\sstop\sBackupExecAgent/ nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string65 = /net\sstop\sbadrv/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string66 = /net\sstop\sbedbg\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string67 = /net\sstop\scbservi/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string68 = /net\sstop\scbvscserv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string69 = /net\sstop\sDCAgent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string70 = /net\sstop\sEhttpSrv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string71 = /net\sstop\sekrn/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string72 = /net\sstop\sEPSecurityService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string73 = /net\sstop\sEPUpdateService.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string74 = /net\sstop\sEsgShKernel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string75 = /net\sstop\sESHASRV/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string76 = /net\sstop\sFA_Scheduler/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string77 = /net\sstop\sfirebirdguardiandefaultinstance/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string78 = /net\sstop\sibmiasrw/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string79 = /net\sstop\sIISADMIN/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string80 = /net\sstop\sIISADMIN/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string81 = /net\sstop\sIMAP4Svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string82 = /net\sstop\sKAVFS/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string83 = /net\sstop\sKAVFSGT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string84 = /net\sstop\skavfsslp/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string85 = /net\sstop\sklnagent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string86 = /net\sstop\smacmnsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string87 = /net\sstop\smasvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string88 = /net\sstop\sMBAMService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string89 = /net\sstop\sMBEndpointAgent.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string90 = /net\sstop\sMcAfeeEngineService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string91 = /net\sstop\sMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string92 = /net\sstop\sMcAfeeFrameworkMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string93 = /net\sstop\sMcShield/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string94 = /net\sstop\smfefire/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string95 = /net\sstop\smfemms/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string96 = /net\sstop\smfevtp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string97 = /net\sstop\smozyprobackup/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string98 = /net\sstop\smr2kserv/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string99 = /net\sstop\sMsDtsServer/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string100 = /net\sstop\sMsDtsServer100/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string101 = /net\sstop\sMsDtsServer110/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string102 = /net\sstop\sMSExchangeADTopology/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string103 = /net\sstop\sMSExchangeFBA/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string104 = /net\sstop\sMSExchangeIS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string105 = /net\sstop\sMSExchangeSA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string106 = /net\sstop\smsftesql\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string107 = /net\sstop\sMSOLAP\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string108 = /net\sstop\sMSOLAP\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string109 = /net\sstop\sMSOLAP\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string110 = /net\sstop\sMSOLAP\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string111 = /net\sstop\sMSSQL\$BKUPEXEC/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string112 = /net\sstop\sMSSQL\$CONTOSO1/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string113 = /net\sstop\sMSSQL\$ECWDB2/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string114 = /net\sstop\sMSSQL\$ISARS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string115 = /net\sstop\sMSSQL\$MSFW/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string116 = /net\sstop\sMSSQL\$PRACTICEMGT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string117 = /net\sstop\sMSSQL\$PRACTTICEBGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string118 = /net\sstop\sMSSQL\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string119 = /net\sstop\sMSSQL\$PROFXENGAGEMENT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string120 = /net\sstop\sMSSQL\$SBSMONITORING/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string121 = /net\sstop\sMSSQL\$SHAREPOINT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string122 = /net\sstop\sMSSQL\$SOPHOS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string123 = /net\sstop\sMSSQL\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string124 = /net\sstop\sMSSQL\$SQLEXPRESS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string125 = /net\sstop\sMSSQL\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string126 = /net\sstop\sMSSQL\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string127 = /net\sstop\sMSSQL\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string128 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string129 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string130 = /net\sstop\sMSSQLServerADHelper100/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string131 = /net\sstop\sMSSQLServerADHelper100/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string132 = /net\sstop\sQBCFMonitorService/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string133 = /net\sstop\sQBPOSDBServiceV12/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string134 = /net\sstop\sQBVSS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string135 = /net\sstop\sQuickBooksDB1/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string136 = /net\sstop\sQuickBooksDB2/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string137 = /net\sstop\sQuickBooksDB3/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string138 = /net\sstop\sQuickBooksDB4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string139 = /net\sstop\sQuickBooksDB5/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string140 = /net\sstop\sReportServer\$ISARS/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string141 = /net\sstop\ssacsvr/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string142 = /net\sstop\sSAVAdminService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string143 = /net\sstop\sSAVService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string144 = /net\sstop\sshadowprotectsvc/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string145 = /net\sstop\sShadowProtectSvc/ nocase ascii wide
        // Description: stopping shared access
        // Reference: N/A
        $string146 = /net\sstop\ssharedaccess/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string147 = /net\sstop\sShMonitor/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string148 = /net\sstop\sSmcinst/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string149 = /net\sstop\sSmcService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string150 = /net\sstop\ssms_site_sql_backup/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string151 = /net\sstop\sSntpService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string152 = /net\sstop\ssophossps/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string153 = /net\sstop\sSPAdminV4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string154 = /net\sstop\sSPSearch4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string155 = /net\sstop\sSPTimerV4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string156 = /net\sstop\sSPTraceV4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string157 = /net\sstop\sSPUserCodeV4/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string158 = /net\sstop\sSPWriterV4/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string159 = /net\sstop\sspxservice/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string160 = /net\sstop\ssqbcoreservice/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string161 = /net\sstop\sSQLAgent\$ISARS/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string162 = /net\sstop\sSQLAgent\$MSFW/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string163 = /net\sstop\sSQLAgent\$SOPH/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string164 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string165 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string166 = /net\sstop\sSQLBrowser/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string167 = /net\sstop\sSQLWriter/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string168 = /net\sstop\sstc_endpt_svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string169 = /net\sstop\sstop\sSepMasterService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string170 = /net\sstop\ssvcGenericHost/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string171 = /net\sstop\sswi_filter/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string172 = /net\sstop\sswi_service/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string173 = /net\sstop\sswi_update/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string174 = /net\sstop\sswi_update_64/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string175 = /net\sstop\sTmCCSF/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string176 = /net\sstop\stmlisten/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string177 = /net\sstop\sTrueKey/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string178 = /net\sstop\sTrueKeyScheduler.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string179 = /net\sstop\sTrueKeyServiceHel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string180 = /net\sstop\svapiendpoint.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string181 = /net\sstop\sVeeamBackupSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string182 = /net\sstop\sVeeamBrokerSvc\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string183 = /net\sstop\sVeeamCatalogSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string184 = /net\sstop\sVeeamCloudSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string185 = /net\sstop\sVeeamDeploymentService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string186 = /net\sstop\sVeeamDeploySvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string187 = /net\sstop\sVeeamDeploySvc.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string188 = /net\sstop\sVeeamEnterpriseManagerSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string189 = /net\sstop\sVeeamHvIntegrationSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string190 = /net\sstop\sVeeamMountSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string191 = /net\sstop\sVeeamNFSSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string192 = /net\sstop\sVeeamRESTSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string193 = /net\sstop\sVeeamTransportSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string194 = /net\sstop\svsnapvss/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string195 = /net\sstop\svssvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string196 = /net\sstop\swbengine/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string197 = /net\sstop\swbengine/ nocase ascii wide
        // Description: stop critical services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string198 = /net\sstop\sWinDefend/ nocase ascii wide
        // Description: stopping AV services
        // Reference: N/A
        $string199 = /net\sstop\sWinDefend/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string200 = /net\sstop\sWRSVC/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string201 = /net\suser\s.{0,1000}\$.{0,1000}\s\// nocase ascii wide
        // Description: activate the guest account in Windows
        // Reference: N/A
        $string202 = /NET\sUSER\sGUEST\s\/ACTIVE\:YES/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string203 = /net\sview\s\/all\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string204 = /net\sview\s\/domain/ nocase ascii wide
        // Description: retrieves a list of shared resources on a remote machine
        // Reference: N/A
        $string205 = /net\sview\s\\\\.{0,1000}\s\/all/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string206 = /net.{0,1000}\sgroup\sAdministrator.{0,1000}\s\/add\s\/domain/ nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string207 = /net\.exe\slocalgroup\s\"Remote\sDesktop\sUsers\"\s.{0,1000}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string208 = /net\.exe\slocalgroup\s.{0,1000}Backup\sOperators/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string209 = /net\.exe\"\slocalgroup\s.{0,1000}Backup\sOperators/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string210 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string211 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string212 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string213 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string214 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string215 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string216 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string217 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string218 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string219 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string220 = /net1\s\sgroup\s\"domain\sadmins\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string221 = /net1\s\sgroup\s\"Domain\sComputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string222 = /net1\s\sgroup\s\"domain\scomputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string223 = /net1\s\sgroup\s\"enterprise\sadmins\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string224 = /net1\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string225 = /net1\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string226 = /net1\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string227 = /net1\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string228 = /net1\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string229 = /net1\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string230 = /net1\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string231 = /net1\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string232 = /net1\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string233 = /net1\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string234 = /net1\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Adds a user account to the local Remote
        // Reference: N/A
        $string235 = /net1\slocalgroup\s\"Remote\sDesktop\sUsers\"\s.{0,1000}\s\/add/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string236 = /net1\slocalgroup\s.{0,1000}Backup\sOperators/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string237 = /net1\slocalgroup\sadmin/ nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string238 = /net1\sstop\sbadrv/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string239 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string240 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string241 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string242 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string243 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string244 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string245 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string246 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string247 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string248 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}
