rule NetSupport
{
    meta:
        description = "Detection patterns for the tool 'NetSupport' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSupport"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string1 = /\s\/EV\"NetSupport\sSchool\"/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string2 = /\/nspowershell\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string3 = /\/nssadmui\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string4 = /\/pcictlui\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string5 = /\/PCIDEPLY\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string6 = /\/Win7Taskbar\.dll/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string7 = /\\ADM\sTemplates\\ADMX\\.{0,1000}\.admx/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string8 = /\\AppData\\Local\\Temp\\.{0,1000}\\NSM\.LIC/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string9 = /\\AppData\\Roaming\\.{0,1000}\\remote\.nsm/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string10 = /\\AppData\\Roaming\\NetSupport\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string11 = /\\NETSUP\~1\\PCIShellExt64\.dll/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string12 = /\\NetSupport\sLtd\\Client32/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string13 = /\\NetSupport\sLtd\\PCICTL/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string14 = /\\netsupport\smanager\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string15 = /\\NetSupport\sSchool\sConsole/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string16 = /\\NetSupport\sSchool\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string17 = /\\NetSupport\sSchool\\NetSupport/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string18 = /\\nspowershell\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string19 = /\\nssadmui\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string20 = /\\pcicfgui_client\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string21 = /\\pciconn\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string22 = /\\PCICTL\\ConfigList\\Standard\\UI\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string23 = /\\pcictlui\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string24 = /\\PCIDEPLY\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string25 = /\\PCINSSCD\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string26 = /\\PCINSSUI\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string27 = /\\PCISCRUI\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string28 = /\\PCIShellExt64\.dll/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string29 = /\\Scripts\\CreateRegKey\.scp/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string30 = /\\Scripts\\DirLst\.log/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string31 = /\\Scripts\\DirLst\.scp/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string32 = /\\Scripts\\DrvSize\.scp/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string33 = /\\Scripts\\writetofile\.scp/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string34 = /\\Software\\NetSupport\sLtd\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string35 = /\\Start\sMenu\\Programs\\NetSupport/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string36 = /\\Win7Taskbar\.dll/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string37 = /_NetSupport_NetSupport\sManager_/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string38 = /\=NetSupport\sClient_deleteme/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string39 = /\>NetSupport\sClient\sApplication\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string40 = /\>NETSUPPORT\sLTD\.\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string41 = /\>NetSupport\sLtd\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string42 = /\>NetSupport\sRemote\sControl\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string43 = /\>NetSupport\sremote\sControl\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string44 = /activate\.netsupportsoftware\.com/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string45 = /Company\'\>NetSupport\sLtd\<\// nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string46 = /geo\.netsupportsoftware\.com/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string47 = /HKCR\\nsm\\shell\\open\\command/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string48 = /HKCR\\NSScriptFile\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string49 = /HKLM\\System\\CurrentControlSet\\Services\\Client32/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string50 = /https\:\/\/nsproducts\.azureedge\.net\/nsm\-.{0,1000}\/NetSupport/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string51 = /NetSupport\sAudio\sSample\sSource\sFilter/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string52 = /NetSupport\sBitmap\sSource\sFilter/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string53 = /NetSupport\sManager\s\-\-\sInstallation\s/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string54 = /NetSupport\sManager\s\(1\)\.msi/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string55 = /NetSupport\sManager\.msi/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string56 = /NetSupport\%20Manager\.msi/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string57 = /netsupport.{0,1000}\\PCISA\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string58 = /netsupport.{0,1000}\\runscrip\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string59 = /netsupport.{0,1000}\\supporttool\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string60 = /NetSupport_Client_machine\.adml/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string61 = /NetSupport_Control_Machine\.adml/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string62 = /NSM_Control_Machine\.adm/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string63 = /pcicfgui_client\.exe.{0,1000}\\Client32\.ini/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string64 = /program\sfiles.{0,1000}\\netsupport\\/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string65 = /\'RuleName\'\>NetSupport\sClient\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string66 = /\'RuleName\'\>NetSupport\sControl\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string67 = /\'RuleName\'\>NetSupport\sDeploy\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string68 = /\'RuleName\'\>NetSupport\sGateway\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string69 = /\'RuleName\'\>NetSupport\sGroup\sLeader\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string70 = /\'RuleName\'\>NetSupport\sRun\sScript\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string71 = /\'RuleName\'\>NetSupport\sScript\sEditor\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string72 = /\'RuleName\'\>NetSupport\sScripting\sAgent\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string73 = /\'RuleName\'\>NetSupport\sTech\sConsole\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string74 = /\'RuleName\'\>NetSupport\sTutor\</ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string75 = /WindowsStoreAppExporter\.exe/ nocase ascii wide
        // Description: NetSupport Manager is a remote access tool that can be used legitimately for IT management but has also been abused  by adversaries for remote system control and surveillance
        // Reference: https://www.netsupportmanager.com/
        $string76 = /winst64\.exe.{0,1000}\s\/q\s\/q\s\/ex\s\/i/ nocase ascii wide

    condition:
        any of them
}
