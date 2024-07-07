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
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string10 = /net\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: List PCs connected to the domain
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string11 = /net\sgroup\s\"domain\scomputers\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string12 = /net\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string13 = /net\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string14 = /net\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string15 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string16 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string18 = /net\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string19 = /net\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string20 = /net\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string21 = /net\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string22 = /net\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string23 = /net\sgroup\s\/domain\s.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string24 = /net\sgroup\sadministrators\s\/domain/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string25 = /net\slocalgroup\sadmin/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string26 = /net\sstop\s\"Sophos\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string27 = /net\sstop\s\"SQL\sBackups\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string28 = /net\sstop\s\"SQLsafe\sBackup\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string29 = /net\sstop\s\"storagecraft\simagemanager.{0,1000}\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string30 = /net\sstop\s\"Symantec\sSystem\sRecovery\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string31 = /net\sstop\s\"Veeam\sBackup\sCatalog\sData\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string32 = /net\sstop\s\"Zoolz\s2\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string33 = /net\sstop\sacronisagent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string34 = /net\sstop\sAcronisAgent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string35 = /net\sstop\sacrsch2svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string36 = /net\sstop\sAcrSch2Svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string37 = /net\sstop\sagntsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string38 = /net\sstop\sAntivirus/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string39 = /net\sstop\sARSM\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string40 = /net\sstop\sarsm/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string41 = /net\sstop\sAVP/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string42 = /net\sstop\sbackp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string43 = /net\sstop\sbackup/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string44 = /net\sstop\sBackupExec/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string45 = /net\sstop\sBackupExecAgent/ nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string46 = /net\sstop\sbadrv/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string47 = /net\sstop\sbedbg\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string48 = /net\sstop\scbservi/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string49 = /net\sstop\scbvscserv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string50 = /net\sstop\sDCAgent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string51 = /net\sstop\sEhttpSrv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string52 = /net\sstop\sekrn/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string53 = /net\sstop\sEPSecurityService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string54 = /net\sstop\sEPUpdateService.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string55 = /net\sstop\sEsgShKernel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string56 = /net\sstop\sESHASRV/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string57 = /net\sstop\sFA_Scheduler/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string58 = /net\sstop\sIMAP4Svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string59 = /net\sstop\sKAVFS/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string60 = /net\sstop\sKAVFSGT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string61 = /net\sstop\skavfsslp/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string62 = /net\sstop\sklnagent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string63 = /net\sstop\smacmnsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string64 = /net\sstop\smasvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string65 = /net\sstop\sMBAMService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string66 = /net\sstop\sMBEndpointAgent.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string67 = /net\sstop\sMcAfeeEngineService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string68 = /net\sstop\sMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string69 = /net\sstop\sMcAfeeFrameworkMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string70 = /net\sstop\sMcShield/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string71 = /net\sstop\smfefire/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string72 = /net\sstop\smfemms/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string73 = /net\sstop\smfevtp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string74 = /net\sstop\smozyprobackup/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string75 = /net\sstop\sMsDtsServer/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string76 = /net\sstop\sMsDtsServer100/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string77 = /net\sstop\sMsDtsServer110/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string78 = /net\sstop\smsftesql\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string79 = /net\sstop\sMSOLAP\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string80 = /net\sstop\sMSOLAP\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string81 = /net\sstop\sMSOLAP\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string82 = /net\sstop\sMSOLAP\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string83 = /net\sstop\sMSSQL\$BKUPEXEC/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string84 = /net\sstop\sMSSQL\$CONTOSO1/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string85 = /net\sstop\sMSSQL\$ECWDB2/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string86 = /net\sstop\sMSSQL\$PRACTICEMGT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string87 = /net\sstop\sMSSQL\$PRACTTICEBGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string88 = /net\sstop\sMSSQL\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string89 = /net\sstop\sMSSQL\$PROFXENGAGEMENT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string90 = /net\sstop\sMSSQL\$SBSMONITORING/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string91 = /net\sstop\sMSSQL\$SHAREPOINT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string92 = /net\sstop\sMSSQL\$SOPHOS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string93 = /net\sstop\sMSSQL\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string94 = /net\sstop\sMSSQL\$SQLEXPRESS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string95 = /net\sstop\sMSSQL\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string96 = /net\sstop\sMSSQL\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string97 = /net\sstop\sMSSQL\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string98 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string99 = /net\sstop\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string100 = /net\sstop\ssacsvr/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string101 = /net\sstop\sSAVAdminService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string102 = /net\sstop\sSAVService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string103 = /net\sstop\sshadowprotectsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string104 = /net\sstop\sShMonitor/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string105 = /net\sstop\sSmcinst/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string106 = /net\sstop\sSmcService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string107 = /net\sstop\ssms_site_sql_backup/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string108 = /net\sstop\sSntpService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string109 = /net\sstop\ssophossps/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string110 = /net\sstop\sspxservice/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string111 = /net\sstop\ssqbcoreservice/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string112 = /net\sstop\sSQLAgent\$SOPH/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string113 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string114 = /net\sstop\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string115 = /net\sstop\sstc_endpt_svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string116 = /net\sstop\sstop\sSepMasterService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string117 = /net\sstop\ssvcGenericHost/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string118 = /net\sstop\sswi_filter/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string119 = /net\sstop\sswi_service/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string120 = /net\sstop\sswi_update/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string121 = /net\sstop\sswi_update_64/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string122 = /net\sstop\sTmCCSF/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string123 = /net\sstop\stmlisten/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string124 = /net\sstop\sTrueKey/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string125 = /net\sstop\sTrueKeyScheduler.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string126 = /net\sstop\sTrueKeyServiceHel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string127 = /net\sstop\svapiendpoint.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string128 = /net\sstop\sVeeamBackupSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string129 = /net\sstop\sVeeamBrokerSvc\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string130 = /net\sstop\sVeeamCatalogSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string131 = /net\sstop\sVeeamCloudSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string132 = /net\sstop\sVeeamDeploymentService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string133 = /net\sstop\sVeeamDeploySvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string134 = /net\sstop\sVeeamDeploySvc.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string135 = /net\sstop\sVeeamEnterpriseManagerSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string136 = /net\sstop\sVeeamHvIntegrationSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string137 = /net\sstop\sVeeamMountSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string138 = /net\sstop\sVeeamNFSSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string139 = /net\sstop\sVeeamRESTSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string140 = /net\sstop\sVeeamTransportSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string141 = /net\sstop\svsnapvss/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string142 = /net\sstop\svssvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string143 = /net\sstop\swbengine/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string144 = /net\sstop\swbengine/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string145 = /net\sstop\sWRSVC/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string146 = /net\suser\s.{0,1000}\$.{0,1000}\s\// nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string147 = /net\sview\s\/all\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string148 = /net\sview\s\/domain/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string149 = /net.{0,1000}\sgroup\sAdministrator.{0,1000}\s\/add\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string150 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string151 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string152 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string153 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string154 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string155 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string156 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string157 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string158 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string159 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string160 = /net1\s\sgroup\s\"domain\sadmins\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string161 = /net1\s\sgroup\s\"Domain\sComputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string162 = /net1\s\sgroup\s\"domain\scomputers\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string163 = /net1\s\sgroup\s\"enterprise\sadmins\"\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: N/A
        $string164 = /net1\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string165 = /net1\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string166 = /net1\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string167 = /net1\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string168 = /net1\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string169 = /net1\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string170 = /net1\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string171 = /net1\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string172 = /net1\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string173 = /net1\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string174 = /net1\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string175 = /net1\slocalgroup\sadmin/ nocase ascii wide
        // Description: Wannacry Ransomware & NOODLERAT behavior
        // Reference: https://www.virustotal.com/gui/file/cde4ca499282045eecd4fc15ac80a232294556a59b3c8c8a7a593e8333cfd3c7/behavior
        $string176 = /net1\sstop\sbadrv/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string177 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string178 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string179 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string180 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string181 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string182 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string183 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string184 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string185 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string186 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}
