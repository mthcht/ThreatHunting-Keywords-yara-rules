rule sc
{
    meta:
        description = "Detection patterns for the tool 'sc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get information about Windows Defender service
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1 = /\s\/c\ssc\squery\sWinDefend/ nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string2 = /dnefedniw\s\seteled\scs/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string3 = /echo\sstart\s\>\s\\\\\.\\pipe\\winreg/ nocase ascii wide
        // Description: disables and stops the KeyIso service (CNG Key Isolation) potentially interfering with cryptographic functions on the system
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L3
        $string4 = /sc\sconfig\sKeyIso\sstart\=\sDisabled\s\|\ssc\sstop\sKeyIso/ nocase ascii wide
        // Description: create service with netcat
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string5 = /sc\screate\s.{0,1000}nc\.exe\s\-.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string6 = /sc\sdelete\s\"AVP18\.0\.0\"/ nocase ascii wide
        // Description: deletes the ESET service
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string7 = /sc\sdelete\s\"ekrn\"/ nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string8 = /sc\sdelete\s\"FirebirdGuardianDefaultInstance\"/ nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string9 = /sc\sdelete\s\"FirebirdServerDefaultInstance\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string10 = /sc\sdelete\s\"hvdswvc\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string11 = /sc\sdelete\s\"klbackupdisk\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string12 = /sc\sdelete\s\"klbackupflt\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string13 = /sc\sdelete\s\"klflt\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string14 = /sc\sdelete\s\"klhk\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string15 = /sc\sdelete\s\"KLIF\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string16 = /sc\sdelete\s\"klim6\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string17 = /sc\sdelete\s\"klkbdflt\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string18 = /sc\sdelete\s\"klmouflt\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string19 = /sc\sdelete\s\"klpd\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string20 = /sc\sdelete\s\"kltap\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string21 = /sc\sdelete\s\"KSDE1\.0\.0\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string22 = /sc\sdelete\s\"ntrtscan\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string23 = /sc\sdelete\s\"nvspwmi\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string24 = /sc\sdelete\s\"ofcservice\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string25 = /sc\sdelete\s\"storflt\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string26 = /sc\sdelete\s\"TmCCSF\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string27 = /sc\sdelete\s\"TmFilter\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string28 = /sc\sdelete\s\"TMiCRCScanService\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string29 = /sc\sdelete\s\"tmlisten\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string30 = /sc\sdelete\s\"TMLWCSService\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string31 = /sc\sdelete\s\"TmPreFilter\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string32 = /sc\sdelete\s\"TmProxy\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string33 = /sc\sdelete\s\"TMSmartRelayService\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string34 = /sc\sdelete\s\"tmusa\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string35 = /sc\sdelete\s\"vmicguestinterface\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string36 = /sc\sdelete\s\"vmicheartbeat\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string37 = /sc\sdelete\s\"vmickvpexchange\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string38 = /sc\sdelete\s\"vmicrdv\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string39 = /sc\sdelete\s\"vmicshutdown\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string40 = /sc\sdelete\s\"vmictimesync\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string41 = /sc\sdelete\s\"vmicvss\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string42 = /sc\sdelete\s\"VSApiNt\"/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string43 = /sc\sdelete\s\"wmms\"/ nocase ascii wide
        // Description: deletes the Webroot service - disabling the antivirus
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string44 = /sc\sdelete\s\"WRSVC\"/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string45 = /sc\sdelete\sAVP18\.0\.0/ nocase ascii wide
        // Description: deletes the ESET service
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string46 = /sc\sdelete\sekrn/ nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string47 = /sc\sdelete\sFirebirdGuardianDefaultInstance/ nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string48 = /sc\sdelete\sFirebirdServerDefaultInstance/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string49 = /sc\sdelete\shvdswvc/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string50 = /sc\sdelete\sklbackupdisk/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string51 = /sc\sdelete\sklbackupflt/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string52 = /sc\sdelete\sklflt/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string53 = /sc\sdelete\sklhk/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string54 = /sc\sdelete\sKLIF/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string55 = /sc\sdelete\sklim6/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string56 = /sc\sdelete\sklkbdflt/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string57 = /sc\sdelete\sklmouflt/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string58 = /sc\sdelete\sklpd/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string59 = /sc\sdelete\skltap/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string60 = /sc\sdelete\sKSDE1\.0\.0/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string61 = /sc\sdelete\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string62 = /sc\sdelete\sMBAMService/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string63 = /sc\sdelete\sntrtscan/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string64 = /sc\sdelete\snvspwmi/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string65 = /sc\sdelete\sofcservice/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string66 = /sc\sdelete\sstorflt/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string67 = /sc\sdelete\sTmCCSF/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string68 = /sc\sdelete\sTmFilter/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string69 = /sc\sdelete\sTMiCRCScanService/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string70 = /sc\sdelete\stmlisten/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string71 = /sc\sdelete\sTMLWCSService/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string72 = /sc\sdelete\sTmPreFilter/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string73 = /sc\sdelete\sTmProxy/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string74 = /sc\sdelete\sTMSmartRelayService/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string75 = /sc\sdelete\stmusa/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string76 = /sc\sdelete\svmicguestinterface/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string77 = /sc\sdelete\svmicheartbeat/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string78 = /sc\sdelete\svmickvpexchange/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string79 = /sc\sdelete\svmicrdv/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string80 = /sc\sdelete\svmicshutdown/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string81 = /sc\sdelete\svmictimesync/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string82 = /sc\sdelete\svmicvss/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string83 = /sc\sdelete\sVSApiNt/ nocase ascii wide
        // Description: deleting the Volume Shadow Copy Service
        // Reference: N/A
        $string84 = /sc\sdelete\sVSS/ nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string85 = /sc\sdelete\swmms/ nocase ascii wide
        // Description: deletes the Webroot service - disabling the antivirus
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string86 = /sc\sdelete\sWRSVC/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string87 = /sc\sqtriggerinfo\sRemoteRegistry/ nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string88 = /sc\ssdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string89 = /sc\sstart\sRemoteRegistry/ nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string90 = /sc\sstop\seventlog/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string91 = /sc\sstop\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string92 = /sc\sstop\sMBAMService/ nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string93 = /sc\sstop\sSophos\sFile\sScanner\sService/ nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string94 = /sc\.exe\ssdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string95 = /sc\.exe\sstop\s.{0,1000}Sophos\sFile\sScanner\sService/ nocase ascii wide
        // Description: Stop Bits service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string96 = /sc\.exe\sstop\sbits/ nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string97 = /sc\.exe\sstop\seventlog/ nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string98 = /sc\.exe.{0,1000}sdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide

    condition:
        any of them
}
