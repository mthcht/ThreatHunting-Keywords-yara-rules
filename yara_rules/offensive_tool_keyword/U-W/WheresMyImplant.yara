rule WheresMyImplant
{
    meta:
        description = "Detection patterns for the tool 'WheresMyImplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WheresMyImplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string1 = /.{0,1000}\/C2\/Beacon\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string2 = /.{0,1000}\/Inject\/Dll\/LoadDll.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string3 = /.{0,1000}\/Inject\/PE\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string4 = /.{0,1000}\/Inject\/ShellCode\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string5 = /.{0,1000}\/KeyLogger\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string6 = /.{0,1000}\/Lateral\/SMB\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string7 = /.{0,1000}\/LoadDllRemote\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string8 = /.{0,1000}\/PE\/InjectPE\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string9 = /.{0,1000}\/Persistence\/InstallUtil\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string10 = /.{0,1000}\/WheresMyImplant\/.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string11 = /.{0,1000}\\WheresMyImplant.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string12 = /.{0,1000}0xbadjuju\/WheresMyImplant.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string13 = /.{0,1000}Collection\/MiniDumpWriteDump\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string14 = /.{0,1000}Credentials\/CacheDump\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string15 = /.{0,1000}Credentials\/LSASecrets\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string16 = /.{0,1000}DumpBrowserHistory.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string17 = /.{0,1000}Empire\.Agent\.Coms\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string18 = /.{0,1000}Empire\.Agent\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string19 = /.{0,1000}Empire\.Agent\.Jobs\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string20 = /.{0,1000}Empire\.Agent\.Stager\..{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string21 = /.{0,1000}InjectPERemote\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string22 = /.{0,1000}InjectPEWMIFSRemote.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string23 = /.{0,1000}InjectShellCode\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string24 = /.{0,1000}InjectShellCodeRemote\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string25 = /.{0,1000}InjectShellCodeWMIFSB64.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string26 = /.{0,1000}Lateral\/DCom\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string27 = /.{0,1000}Lateral\/PSExec\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string28 = /.{0,1000}Lateral\/SMBClient\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string29 = /.{0,1000}Lateral\/SMBClientDelete\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string30 = /.{0,1000}Lateral\/SMBClientGet\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string31 = /.{0,1000}Lateral\/SMBClientPut\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string32 = /.{0,1000}Lateral\/WMIExec\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string33 = /.{0,1000}namespace\sWheresMyImplant.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string34 = /.{0,1000}Persistence\/InstallWMI.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string35 = /.{0,1000}PTHSMBClientDelete.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string36 = /.{0,1000}PTHSMBClientGet.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string37 = /.{0,1000}PTHSMBClientList.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string38 = /.{0,1000}PTHSMBClientPut.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string39 = /.{0,1000}PTHSMBExec.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string40 = /.{0,1000}PTHWMIExec.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string41 = /.{0,1000}root\\cimv2:Win32_Implant.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string42 = /.{0,1000}StartWebServiceBeacon.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string43 = /.{0,1000}WheresMyImplant\.cs.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string44 = /.{0,1000}WheresMyImplant\.git.{0,1000}/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string45 = /.{0,1000}WheresMyImplant\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
