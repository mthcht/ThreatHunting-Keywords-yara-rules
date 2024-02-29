rule Zoho_Assist
{
    meta:
        description = "Detection patterns for the tool 'Zoho Assist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zoho Assist"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string1 = /\s\-altgw\s.{0,1000}\.zohoassist\.com\s/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string2 = /\s\-ms\sassist\.zoho\.com\s\-p\s443/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string3 = /\s\-rr_flag\s.{0,1000}\s\-group\s.{0,1000}\s\-fileTransferGateways\s.{0,1000}\.zohoassist\.com\s\-ADMINAGENT/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string4 = /\sSELECT\sProcessId\sFROM\sWin32_Process\s.{0,1000}\sName\=\'ZAAudioClient\.exe\'/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string5 = /\sZA_Connect\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string6 = /\sZAAudioClient\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string7 = /\sZAFileTransfer\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string8 = /\sZAService\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string9 = /\.zohoassist\.com\.cn/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string10 = /\.zohoassist\.jp/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string11 = /\/ZA_Connect\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string12 = /\/ZAAudioClient\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string13 = /\/ZAFileTransfer\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string14 = /\/ZAService\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string15 = /\\AppData\\Local\\ZohoMeeting\\/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string16 = /\\CurrentControlSet\\Services\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string17 = /\\dctoolshardware\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string18 = /\\InventoryApplicationFile\\zaservice\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string19 = /\\log\\FileTransferWindowAppLog\.log/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string20 = /\\Root\\InventoryApplicationFile\\za_connect\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string21 = /\\RSTemp\\ZohoMeeting\\/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string22 = /\\SafeBoot\\Network\\Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string23 = /\\SOFTWARE\\Zoho\sAssist/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string24 = /\\ZA_Connect\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string25 = /\\ZA_Upgrader/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string26 = /\\ZAAudioClient\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string27 = /\\ZAFileTransfer\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string28 = /\\ZAService\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string29 = /\\ZAudioClientPipe_.{0,1000}ServerReadPipe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string30 = /\\ZAudioClientPipe_.{0,1000}ServerWritePipe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string31 = /\\ZMAgent\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string32 = /\\Zoho\sAssist\\Zoho\sAssist\sRemote\ssupport/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string33 = /\\ZohoMeeting\.7z/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string34 = /\\ZohoMeeting\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string35 = /\\ZohoMeeting\\agent\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string36 = /\\zohomeeting\\agent\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string37 = /\\ZohoMeeting\\agent_ui\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string38 = /\\ZohoMeeting\\Connect\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string39 = /\\ZohoMeeting\\Connection\.conf/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string40 = /\\ZohoMeeting\\log\\.{0,1000}\.log/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string41 = /\\ZohoMeeting\\ViewerUI\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string42 = /\\ZohoTray\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string43 = /\\ZohoURS\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string44 = /\\ZohoURSService\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string45 = /_Classes\\zohoassistlaunchv2/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string46 = /assist\.zoho\.com/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string47 = /downloads\.zohocdn\.com/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string48 = /downloads\.zohodl\.com\.cn/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string49 = /gateway\.zohoassist\.com/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string50 = /https\:\/\/.{0,1000}\.zoho\.com\/pconnect/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string51 = /https\:\/\/.{0,1000}\.zohoassist\.com\/w_socket/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string52 = /https\:\/\/assist\.zoho\.com\/assist\-join\?key\=/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string53 = /https\:\/\/assist\.zoho\.com\/customer\-session\-details\?client_token\=/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string54 = /https\:\/\/assist\.zoho\.com\/join\?join_source\=EMAIL_INVITE/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string55 = /https\:\/\/assist\.zoho\.com\/join\-session\?key\=/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string56 = /https\:\/\/assist\.zoho\.com\/org\// nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string57 = /https\:\/\/assist\.zoho\.com\/viewer\-assist/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string58 = /https\:\/\/pubsub\.zoho\.com\/.{0,1000}_deskUserPresence\/pubsub/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string59 = /https\:\/\/us4\-wms6\.zoho\.com/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string60 = /ProductName\:Zoho\%\%20Assist.{0,1000}\sapptype\:ATTENDEE/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string61 = /program\sfiles\s\(x86\)\\zohomeeting/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string62 = /\'ServiceName\'\>Zoho\sAssist\-Remote\sSupport/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string63 = /turn\-.{0,1000}\.zohomeeting\.com/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string64 = /ZA_Connect\.exe\s/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string65 = /ZA_Connect\.exe\.ApplicationCompany/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string66 = /ZAFileTransfer\.exe\s/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string67 = /ZAService\.exe\s/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string68 = /ZOHO\sCORPORATION\sPRIVATE\sLIMITED/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string69 = /ZohoMeeting\.exe/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string70 = /ZohoMeeting\\FileTransferSettings\.conf/ nocase ascii wide
        // Description: Zoho Assist Remote access software - abused by attackers
        // Reference: https://www.zoho.com/assist/
        $string71 = /ZohoMeeting\\Service\.Conf/ nocase ascii wide

    condition:
        any of them
}
