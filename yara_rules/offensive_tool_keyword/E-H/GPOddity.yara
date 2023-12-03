rule GPOddity
{
    meta:
        description = "Detection patterns for the tool 'GPOddity' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPOddity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string1 = /.{0,1000}\s\'46993522\-7D77\-4B59\-9B77\-F82082DE9D81\'\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string2 = /.{0,1000}\s\'GPODDITY\$\'\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string3 = /.{0,1000}\s\-\-gpo\-id\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-command\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string4 = /.{0,1000}\s\-\-gpo\-id\s.{0,1000}\s\-\-gpo\-type\s.{0,1000}\s\-\-no\-smb\-server\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string5 = /.{0,1000}\s\-\-rogue\-smbserver\-ip\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string6 = /.{0,1000}\s\-\-rogue\-smbserver\-share\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string7 = /.{0,1000}\(not\slaunching\sGPOddity\sSMB\sserver\).{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string8 = /.{0,1000}\/GPOddity\.git.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string9 = /.{0,1000}\/GPOddity\/.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string10 = /.{0,1000}\[\!\]\sFailed\sto\sdownload\slegitimate\sGPO\sfrom\sSYSVOL\s\(dc_ip:.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string11 = /.{0,1000}\[\!\]\sFailed\sto\swrite\smalicious\sscheduled\stask\sto\sdownloaded\sGPO\.\sExiting.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string12 = /.{0,1000}\[.{0,1000}\]\sDownloading\sthe\slegitimate\sGPO\sfrom\sSYSVOL.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string13 = /.{0,1000}\[.{0,1000}\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string14 = /.{0,1000}\[.{0,1000}\]\sUpdating\sdownloaded\sGPO\sversion\snumber\sto\sensure\sautomatic\sGPO\sapplication.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string15 = /.{0,1000}\[\+\]\sSuccessfully\sdownloaded\slegitimate\sGPO\sfrom\sSYSVOL\sto\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string16 = /.{0,1000}\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string17 = /.{0,1000}\[\+\]\sSuccessfully\sspoofed\sGPC\sgPCFileSysPath\sattribute.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string18 = /.{0,1000}\\GPOddity\\.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string19 = /.{0,1000}\=\=\=\sGENERATING\sMALICIOUS\sGROUP\sPOLICY\sTEMPLATE\s\=\=\=.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string20 = /.{0,1000}Could\snot\swrite\sNTLM\sHashes\sto\sthe\sspecified\sJTR_Dump_Path\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string21 = /.{0,1000}Couldn\'t\sclone\sGPO\s{}\s\(maybe\sit\sdoes\snot\sexist\?.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string22 = /.{0,1000}from\shelpers\..{0,1000}_smbserver\s.{0,1000}\simport\sSimpleSMBServer.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string23 = /.{0,1000}gpoddity\.py.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string24 = /.{0,1000}gpoddity_smbserver\.py.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string25 = /.{0,1000}GPOddity\-master.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string26 = /.{0,1000}helpers\.gpoddity_smbserver.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string27 = /.{0,1000}If\sthe\sattack\sis\ssuccessful.{0,1000}\syou\swill\ssee\sauthentication\slogs\sof\smachines\sretrieving\sand\sexecuting\sthe\smalicious\sGPO.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string28 = /.{0,1000}\-\-just\-clean.{0,1000}cleaning\/to_clean\.txt.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string29 = /.{0,1000}LAUNCHING\sGPODDITY\sSMB\sSERVER\sAND\sWAITING\sFOR\sGPO\sREQUESTS.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string30 = /.{0,1000}net\suser\sjohn\sH4x00r123.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string31 = /.{0,1000}scheduledtask_utils\.py\s.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string32 = /.{0,1000}SPOOFING\sGROUP\sPOLICY\sTEMPLATE\sLOCATION\sTHROUGH\sgPCFileSysPath.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string33 = /.{0,1000}synacktiv\/GPOddity.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string34 = /.{0,1000}synacktiv_gpoddity.{0,1000}/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string35 = /.{0,1000}You\sare\strying\sto\starget\sa\sUser\sGroup\sPolicy\sObject\swhile\srunning\sthe\sembedded\sSMB\sserver.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
