rule taskkill
{
    meta:
        description = "Detection patterns for the tool 'taskkill' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "taskkill"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: forcefully kills processes based on a process ID (PID greater than or equal to 1000) has been used to disrupt various processes while avoiding certain window
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string1 = "TASKKILL /F /FI \"PID ge 1000\" /FI \"WINDOWTITLE ne untitled" nocase ascii wide
        // Description: killing lsass process
        // Reference: https://x.com/malmoeb/status/1741114854037987437
        $string2 = /taskkill\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
        // Description: evade EDR/AV by repairing with msiexec and killing the process
        // Reference: https://badoption.eu/blog/2024/03/23/cortex.html
        $string3 = /taskkill\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide
        // Description: stopping Backup Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string4 = /taskkill\s\/im\sagntsvc\.exe\s\/F/ nocase ascii wide
        // Description: stopping Network Management
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string5 = /taskkill\s\/IM\sCNTAoSMgr\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string6 = /taskkill\s\/im\sdbeng50\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string7 = /taskkill\s\/im\sdbsnmp\.exe\s\/F/ nocase ascii wide
        // Description: stopping Encryption Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string8 = /taskkill\s\/im\sencsvc\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string9 = /taskkill\s\/im\sexcel\.exe\s\/F/ nocase ascii wide
        // Description: stopping Browser Configuration
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string10 = /taskkill\s\/im\sfirefoxconfig\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string11 = /taskkill\s\/im\sinfopath\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string12 = /taskkill\s\/im\sisqlplussvc\.exe\s\/F/ nocase ascii wide
        // Description: stopping Antivirus
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string13 = /taskkill\s\/IM\smbamtray\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string14 = /taskkill\s\/im\smsaccess\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string15 = /taskkill\s\/im\smsftesql\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string16 = /taskkill\s\/im\smspub\.exe\s\/F/ nocase ascii wide
        // Description: stopping Remote Desktop Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string17 = /taskkill\s\/im\smydesktopqos\.exe\s\/F/ nocase ascii wide
        // Description: stopping Remote Desktop Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string18 = /taskkill\s\/im\smydesktopservice\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string19 = /taskkill\s\/im\smysqld\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string20 = /taskkill\s\/im\smysqld\-nt\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string21 = /taskkill\s\/im\smysqld\-opt\.exe\s\/F/ nocase ascii wide
        // Description: stopping Antivirus
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string22 = "taskkill /IM Ntrtsc" nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string23 = /taskkill\s\/im\socautoupds\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string24 = /taskkill\s\/im\socomm\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string25 = /taskkill\s\/im\socssd\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string26 = /taskkill\s\/im\sonenote\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string27 = /taskkill\s\/im\soracle\.exe\s\/F/ nocase ascii wide
        // Description: stopping Email Client
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string28 = /taskkill\s\/im\soutlook\.exe\s\/F/ nocase ascii wide
        // Description: stopping Antivirus
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string29 = /taskkill\s\/IM\sPccNTMon\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string30 = /taskkill\s\/im\spowerpnt\.exe\s\/F/ nocase ascii wide
        // Description: stopping Antivirus
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string31 = /taskkill\s\/im\ssavfmsesp\.exe\s\/f/ nocase ascii wide
        // Description: stopping Database Backup
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string32 = /taskkill\s\/im\ssqbcoreservice\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string33 = /taskkill\s\/im\ssqlagent\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string34 = /taskkill\s\/im\ssqlbrowser\.exe\s\/F/ nocase ascii wide
        // Description: stopping Database Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string35 = /taskkill\s\/im\ssqlservr\.exe\s\/F/ nocase ascii wide
        // Description: stopping Synchronization Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string36 = /taskkill\s\/im\ssynctime\.exe\s\/F/ nocase ascii wide
        // Description: stopping Email Client Configuration
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string37 = /taskkill\s\/im\stbirdconfig\.exe\s\/F/ nocase ascii wide
        // Description: stopping Email Client
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string38 = /taskkill\s\/im\sthebat\.exe\s\/F/ nocase ascii wide
        // Description: stopping Email Client
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string39 = /taskkill\s\/im\sthebat64\.exe\s\/F/ nocase ascii wide
        // Description: stopping Email Client
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string40 = /taskkill\s\/im\sthunderbird\.exe\s\/F/ nocase ascii wide
        // Description: stopping Antivirus
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string41 = /taskkill\s\/IM\stmlisten\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string42 = /taskkill\s\/im\svisio\.exe\s\/F/ nocase ascii wide
        // Description: stopping Office Application
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string43 = /taskkill\s\/im\swinword\.exe\s\/F/ nocase ascii wide
        // Description: stopping Text Editor
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string44 = /taskkill\s\/im\swordpad\.exe\s\/F/ nocase ascii wide
        // Description: stopping Financial Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string45 = /taskkill\s\/im\sxfssvccon\.exe\s\/F/ nocase ascii wide
        // Description: stopping Backup Service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string46 = /taskkill\s\/im\szoolz\.exe\s\/F/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string47 = /taskkill\s\-f\s\-im\sfdhost\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string48 = /taskkill\s\-f\s\-im\sfdlauncher\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string49 = /taskkill\s\-f\s\-im\sfdlauncher\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string50 = /taskkill\s\-f\s\-im\sMsDtsSrvr\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string51 = /taskkill\s\-f\s\-im\smsftesql\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string52 = /taskkill\s\-f\s\-im\smsmdsrv\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string53 = /taskkill\s\-f\s\-im\spg_ctl\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string54 = /taskkill\s\-f\s\-im\spostgres\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string55 = /taskkill\s\-f\s\-im\sReportingServicesService\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string56 = /taskkill\s\-f\s\-im\sSQLAGENT\.EXE/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string57 = /taskkill\s\-f\s\-im\ssqlbrowser\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string58 = /taskkill\s\-f\s\-im\ssqlceip\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string59 = /taskkill\s\-f\s\-im\ssqlservr\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string60 = /taskkill\s\-f\s\-im\ssqlservr\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string61 = /taskkill\s\-f\s\-im\ssqlwriter\.exe/ nocase ascii wide
        // Description: terminate processes related to SQL servers
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string62 = /taskkill\s\-f\s\-im\sSsms\.exe/ nocase ascii wide
        // Description: killing lsass process
        // Reference: https://x.com/malmoeb/status/1741114854037987437
        $string63 = /taskkill\.exe\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
        // Description: evade EDR/AV by repairing with msiexec and killing the process
        // Reference: https://badoption.eu/blog/2024/03/23/cortex.html
        $string64 = /taskkill\.exe\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide

    condition:
        any of them
}
