rule RemotePotato0
{
    meta:
        description = "Detection patterns for the tool 'RemotePotato0' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePotato0"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string1 = /\sprinting\sthe\sgolden\sdata\,\sformat\sinspired\sby\sResponder\s\:D/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string2 = /\sRemotePotato0\.zip/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string3 = /\sRogueOxidResolver\smust\sbe\srun\sremotely/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string4 = /\s\-s\s127\.0\.0\.1\s\-e\s.{0,1000}\s\-a\sconnect\s\-u\sntlm/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string5 = /\#include\s\"RogueOxidResolver\.h/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string6 = /\.py\s\-t\sldap\:\/\/.{0,1000}\s\-\-no\-wcf\-server\s\-\-escalate\-user\s/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string7 = /\/RemotePotato0\.git/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string8 = /\/RemotePotato0\.zip/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string9 = /\[\!\]\sCouldn\'t\scapture\sthe\suser\scredential\shash\s\:/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string10 = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string11 = /\[\!\]\sCouldn\'t\sreceive\sthe\stype2\smessage\sfrom\sthe\sfake\sRPC\sServer/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string12 = /\[\+\]\sRelaying\sseems\ssuccessfull\,\scheck\sntlmrelayx\soutput\!/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string13 = /\[\+\]\sUser\shash\sstolen\!/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string14 = /\\RemotePotato0\.cpp/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string15 = /\\RemotePotato0\.sln/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string16 = /\\RemotePotato0\.zip/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string17 = /\\RemotePotato0\-main\.zip/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string18 = /\\RemotePotato0\-main\\/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string19 = /\\RogueOxidResolver\.cpp/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string20 = /\]\sStarting\sRogueOxidResolver\sRPC\sServer\slistening\son\sport/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string21 = /\]\sStarting\sthe\sNTLM\srelay\sattack\,\slaunch\sntlmrelayx\son\s/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string22 = /\]\sStarting\sthe\sRPC\sserver\sto\scapture\sthe\scredentials\shash\sfrom\sthe\suser\sauthentication\!\!/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string23 = /1c6b60ff20f7c26a7436d966fc741ecd05dc2b3326de1ebcd7fcf6142ac24409/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string24 = /antonioCoco\/RemotePotato0/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string25 = /B88B65D3\-2689\-4E39\-892C\-7532087174CB/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string26 = /Detected\sa\sWindows\sServer\sversion\snot\scompatible\swith\sJuicyPotato/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string27 = /ntlmrelayx\.py/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string28 = /RemotePotato0.{0,1000}\@splinter_code\s\&\s\@decoder_it/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string29 = /RemotePotato0\.exe/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string30 = /RogueOxidResolver\scan\sbe\srun\slocally\son\s127\.0\.0\.1/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string31 = /sudo\ssocat\s\-v\sTCP\-LISTEN\:135.{0,1000}rogueOxidResolverPort/ nocase ascii wide
        // Description: Windows Privilege Escalation from User to Domain Admin.
        // Reference: https://github.com/antonioCoco/RemotePotato0
        $string32 = /you\scannot\srun\sthe\sRogueOxidResolver\son\s127\.0\.0\.1/ nocase ascii wide

    condition:
        any of them
}
