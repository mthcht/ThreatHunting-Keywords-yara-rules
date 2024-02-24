rule LogMeIn
{
    meta:
        description = "Detection patterns for the tool 'LogMeIn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LogMeIn"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string1 = /\.console\.gotoassist\.com/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string2 = /\.remoteview\.logmein\.com/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string3 = /\/LMI_Rescue\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string4 = /\/LMIRTechConsole\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string5 = /\\AppData\\Local\\.{0,1000}\\rescue\.log/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string6 = /\\AppData\\Local\\LMIR.{0,1000}\.tmp\.bat/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string7 = /\\AppData\\Local\\LogMeIn\sRescue\sApplet\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string8 = /\\AppData\\LocalLow\\LogMeIn\sRescue\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string9 = /\\LMI_Rescue\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string10 = /\\lmi_rescue_srv\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string11 = /\\LMIGuardianEvt\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string12 = /\\LMIR.{0,1000}\.tmp\\rarcc\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string13 = /\\LMIRescue\-.{0,1000}\.clog/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string14 = /\\LMIRescue\-.{0,1000}\.connlog/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string15 = /\\LMIRescueCOL\.log/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string16 = /\\LMIRescueMqttMessages_.{0,1000}\.dat/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string17 = /\\LMIRescueUpdater\.log/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string18 = /\\LMIRhook\.000\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string19 = /\\lmirtechconsole\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string20 = /\\LMIRTechConsole\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string21 = /\\LMITrs\-.{0,1000}\.trs/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string22 = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string23 = /\\LogMeIn\sRescue\sApplet\\LMIR/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string24 = /\\LogMeIn\sRescue\sAVI\sCodec\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string25 = /\\logmein\srescue\stechnician\sconsole\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string26 = /\\LogMeIn\\Dumps\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string27 = /\\LogMeInRescue_ipc/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string28 = /\\LogMeInRescue_rarc_r_/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string29 = /\\LogMeInRescue_rarc_w_/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string30 = /\\LogMeInRescueTechnicianConsole_x64/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string31 = /\\ProgramData\\LogMeIn\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string32 = /\\ractrlkeyhook\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string33 = /\\RescueWinRTLib\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string34 = /\\RescueWinRTLib\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string35 = /\\Root\\InventoryApplicationFile\\support\-logmeinr/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string36 = /\\RunOnce\\.{0,1000}LogMeInRescue_/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string37 = /\\Software\\LogMeInRescue\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string38 = /\\Start\sMenu\\Programs\\LogMeIn\sRescue\\/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string39 = /\\Start\sMenu\\Programs\\LogMeIn/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string40 = /\<Data\>LogMeIn\,\sInc\.\<\/Data\>/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string41 = /9d2ce0345f4ee5798a49a8a13e33c7502a2ac655/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string42 = /control\..{0,1000}\.logmeinrescue\.com/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string43 = /control\.rsc\-app.{0,1000}\.logmeinrescue\.com/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string44 = /https\:\/\/secure\.logmeinrescue\.com\/R\?i\=2\&Code\=/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string45 = /https\:\/\/secure\.logmeinrescue\.com\/TechnicianConsole\/Launch/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string46 = /LMI_RescueRC\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string47 = /LMIGuardianDll\.dll/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string48 = /LMIGuardianSvc\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string49 = /LogMeIn\sRescue\sTechnician\sConsole\.lnk/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string50 = /LogMeInRescueTechnicianConsoleApp\.msi/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string51 = /Support\-LogMeInRescue\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string52 = /Support\-LogMeInRescue\.exe/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string53 = /SUPPORT\-LOGMEINRESCUE\.EXE\-/ nocase ascii wide
        // Description: LogMeIn is a legitimate remote support software that allows IT and customer support teams to remotely access and control devices to provide support - abused by threat actors 
        // Reference: https://www.logmein.com
        $string54 = /turn\.console\.gotoassist\.com/ nocase ascii wide

    condition:
        any of them
}
