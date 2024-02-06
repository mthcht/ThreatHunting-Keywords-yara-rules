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
        $string1 = /\s\'46993522\-7D77\-4B59\-9B77\-F82082DE9D81\'\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string2 = /\s\'GPODDITY\$\'\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string3 = /\s\-\-gpo\-id\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-command\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string4 = /\s\-\-gpo\-id\s.{0,1000}\s\-\-gpo\-type\s.{0,1000}\s\-\-no\-smb\-server\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string5 = /\s\-\-rogue\-smbserver\-ip\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string6 = /\s\-\-rogue\-smbserver\-share\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string7 = /\(not\slaunching\sGPOddity\sSMB\sserver\)/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string8 = /\/GPOddity\.git/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string9 = /\/GPOddity\// nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string10 = /\[\!\]\sFailed\sto\sdownload\slegitimate\sGPO\sfrom\sSYSVOL\s\(dc_ip\:/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string11 = /\[\!\]\sFailed\sto\swrite\smalicious\sscheduled\stask\sto\sdownloaded\sGPO\.\sExiting/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string12 = /\[.{0,1000}\]\sDownloading\sthe\slegitimate\sGPO\sfrom\sSYSVOL/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string13 = /\[.{0,1000}\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string14 = /\[.{0,1000}\]\sUpdating\sdownloaded\sGPO\sversion\snumber\sto\sensure\sautomatic\sGPO\sapplication/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string15 = /\[\+\]\sSuccessfully\sdownloaded\slegitimate\sGPO\sfrom\sSYSVOL\sto\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string16 = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string17 = /\[\+\]\sSuccessfully\sspoofed\sGPC\sgPCFileSysPath\sattribute/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string18 = /\\GPOddity\\/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string19 = /\=\=\=\sGENERATING\sMALICIOUS\sGROUP\sPOLICY\sTEMPLATE\s\=\=\=/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string20 = /Could\snot\swrite\sNTLM\sHashes\sto\sthe\sspecified\sJTR_Dump_Path\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string21 = /Couldn\'t\sclone\sGPO\s\{\}\s\(maybe\sit\sdoes\snot\sexist\?/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string22 = /from\shelpers\..{0,1000}_smbserver\s.{0,1000}\simport\sSimpleSMBServer/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string23 = /gpoddity\.py/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string24 = /gpoddity_smbserver\.py/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string25 = /GPOddity\-master/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string26 = /helpers\.gpoddity_smbserver/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string27 = /If\sthe\sattack\sis\ssuccessful.{0,1000}\syou\swill\ssee\sauthentication\slogs\sof\smachines\sretrieving\sand\sexecuting\sthe\smalicious\sGPO/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string28 = /\-\-just\-clean.{0,1000}cleaning\/to_clean\.txt/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string29 = /LAUNCHING\sGPODDITY\sSMB\sSERVER\sAND\sWAITING\sFOR\sGPO\sREQUESTS/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string30 = /net\suser\sjohn\sH4x00r123/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string31 = /scheduledtask_utils\.py\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string32 = /SPOOFING\sGROUP\sPOLICY\sTEMPLATE\sLOCATION\sTHROUGH\sgPCFileSysPath/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string33 = /synacktiv\/GPOddity/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string34 = /synacktiv_gpoddity/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string35 = /You\sare\strying\sto\starget\sa\sUser\sGroup\sPolicy\sObject\swhile\srunning\sthe\sembedded\sSMB\sserver/ nocase ascii wide

    condition:
        any of them
}
