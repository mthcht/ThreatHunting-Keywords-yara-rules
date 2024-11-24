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
        $string1 = " /c sc query WinDefend" nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string2 = "dnefedniw  eteled cs" nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string3 = /echo\sstart\s\>\s\\\\\.\\pipe\\winreg/ nocase ascii wide
        // Description: disables and stops the KeyIso service (CNG Key Isolation) potentially interfering with cryptographic functions on the system
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L3
        $string4 = /sc\sconfig\sKeyIso\sstart\=\sDisabled\s\|\ssc\sstop\sKeyIso/ nocase ascii wide
        // Description: create service with netcat
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string5 = /sc\screate\s.{0,100}nc\.exe\s\-.{0,100}cmd\.exe/ nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string6 = /sc\sdelete\s\\"AVP18\.0\.0\\"/ nocase ascii wide
        // Description: deletes the ESET service
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string7 = "sc delete \"ekrn\"" nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string8 = "sc delete \"FirebirdGuardianDefaultInstance\"" nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string9 = "sc delete \"FirebirdServerDefaultInstance\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string10 = "sc delete \"hvdswvc\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string11 = "sc delete \"klbackupdisk\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string12 = "sc delete \"klbackupflt\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string13 = "sc delete \"klflt\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string14 = "sc delete \"klhk\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string15 = "sc delete \"KLIF\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string16 = "sc delete \"klim6\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string17 = "sc delete \"klkbdflt\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string18 = "sc delete \"klmouflt\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string19 = "sc delete \"klpd\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string20 = "sc delete \"kltap\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string21 = /sc\sdelete\s\\"KSDE1\.0\.0\\"/ nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string22 = "sc delete \"ntrtscan\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string23 = "sc delete \"nvspwmi\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string24 = "sc delete \"ofcservice\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string25 = "sc delete \"storflt\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string26 = "sc delete \"TmCCSF\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string27 = "sc delete \"TmFilter\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string28 = "sc delete \"TMiCRCScanService\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string29 = "sc delete \"tmlisten\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string30 = "sc delete \"TMLWCSService\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string31 = "sc delete \"TmPreFilter\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string32 = "sc delete \"TmProxy\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string33 = "sc delete \"TMSmartRelayService\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string34 = "sc delete \"tmusa\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string35 = "sc delete \"vmicguestinterface\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string36 = "sc delete \"vmicheartbeat\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string37 = "sc delete \"vmickvpexchange\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string38 = "sc delete \"vmicrdv\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string39 = "sc delete \"vmicshutdown\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string40 = "sc delete \"vmictimesync\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string41 = "sc delete \"vmicvss\"" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string42 = "sc delete \"VSApiNt\"" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string43 = "sc delete \"wmms\"" nocase ascii wide
        // Description: deletes the Webroot service - disabling the antivirus
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string44 = "sc delete \"WRSVC\"" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string45 = /sc\sdelete\sAVP18\.0\.0/ nocase ascii wide
        // Description: deletes the ESET service
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string46 = "sc delete ekrn" nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string47 = "sc delete FirebirdGuardianDefaultInstance" nocase ascii wide
        // Description: delete services related to the Firebird database 
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string48 = "sc delete FirebirdServerDefaultInstance" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string49 = "sc delete hvdswvc" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string50 = "sc delete klbackupdisk" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string51 = "sc delete klbackupflt" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string52 = "sc delete klflt" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string53 = "sc delete klhk" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string54 = "sc delete KLIF" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string55 = "sc delete klim6" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string56 = "sc delete klkbdflt" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string57 = "sc delete klmouflt" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string58 = "sc delete klpd" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string59 = "sc delete kltap" nocase ascii wide
        // Description: delete Kaspersky services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string60 = /sc\sdelete\sKSDE1\.0\.0/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string61 = "sc delete MBAMProtection" nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string62 = "sc delete MBAMService" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string63 = "sc delete ntrtscan" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string64 = "sc delete nvspwmi" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string65 = "sc delete ofcservice" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string66 = "sc delete storflt" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string67 = "sc delete TmCCSF" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string68 = "sc delete TmFilter" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string69 = "sc delete TMiCRCScanService" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string70 = "sc delete tmlisten" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string71 = "sc delete TMLWCSService" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string72 = "sc delete TmPreFilter" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string73 = "sc delete TmProxy" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string74 = "sc delete TMSmartRelayService" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string75 = "sc delete tmusa" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string76 = "sc delete vmicguestinterface" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string77 = "sc delete vmicheartbeat" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string78 = "sc delete vmickvpexchange" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string79 = "sc delete vmicrdv" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string80 = "sc delete vmicshutdown" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string81 = "sc delete vmictimesync" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string82 = "sc delete vmicvss" nocase ascii wide
        // Description: delete Trend Micro services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string83 = "sc delete VSApiNt" nocase ascii wide
        // Description: deleting the Volume Shadow Copy Service
        // Reference: N/A
        $string84 = "sc delete VSS" nocase ascii wide
        // Description: delete Hyper-V related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string85 = "sc delete wmms" nocase ascii wide
        // Description: deletes the Webroot service - disabling the antivirus
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string86 = "sc delete WRSVC" nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string87 = "sc qtriggerinfo RemoteRegistry" nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string88 = /sc\ssdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string89 = "sc start RemoteRegistry" nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string90 = "sc stop eventlog" nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string91 = "sc stop MBAMProtection" nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string92 = "sc stop MBAMService" nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string93 = "sc stop Sophos File Scanner Service" nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string94 = /sc\.exe\ssdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string95 = /sc\.exe\sstop\s.{0,100}Sophos\sFile\sScanner\sService/ nocase ascii wide
        // Description: Stop Bits service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string96 = /sc\.exe\sstop\sbits/ nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string97 = /sc\.exe\sstop\seventlog/ nocase ascii wide
        // Description: creates a backdoor by weakening the security of the Service Control Manager allowing any user to manage services on the machine which can lead to privilege escalation and persistent access by an attacker
        // Reference: https://x.com/0gtweet/status/1628720819537936386
        $string98 = /sc\.exe.{0,100}sdset\sscmanager\sD\:\(A\;\;KA\;\;\;WD\)/ nocase ascii wide
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
