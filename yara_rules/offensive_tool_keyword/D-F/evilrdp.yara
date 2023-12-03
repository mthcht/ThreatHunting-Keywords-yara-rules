rule evilrdp
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string1 = /.{0,1000}\sevilrdp\.gui\s.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string2 = /.{0,1000}\/evilrdp\.git.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string3 = /.{0,1000}\/evilrdp\/.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string4 = /.{0,1000}\\evilrdp\\.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string5 = /.{0,1000}aardwolf\.extensions\.RDPEDYC\.vchannels\.socksoverrdp\simport\sSocksOverRDPChannel.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string6 = /.{0,1000}aiocmd\\nested_completer\.py.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string7 = /.{0,1000}Async\sRDP\sClient\.\sDuckyscript\swill\sbe\sexecuted\sby\spressing\sESC\s3\stimes.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string8 = /.{0,1000}do_socksoverrdp\(.{0,1000}127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string9 = /.{0,1000}do_socksproxy\(.{0,1000}\slisten_ip\s\=\s\'127\.0\.0\.1\'.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string10 = /.{0,1000}do_startpscmd\(.{0,1000}serverscript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string11 = /.{0,1000}ducky_keyboard_sender\(scancode.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string12 = /.{0,1000}Emulates\sa\srightclick\son\sthe\sgiven\scoordinates.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string13 = /.{0,1000}evilrdp\.exe.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string14 = /.{0,1000}evilrdp\-main.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string15 = /.{0,1000}Executes\sa\spowershell\scommand\son\sthe\sremote\shost\.\sRequires\sPSCMD.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string16 = /.{0,1000}from\sevilrdp\.consolehelper.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string17 = /.{0,1000}import\sEVILRDPConsole.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string18 = /.{0,1000}import\sEvilRDPGUI.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string19 = /.{0,1000}PSCMD\schannel\swas\seither\snot\sdefined\swhile\sconnecting\sOR\sthe\schannel\sname\sis\snot\sthe\sdefault\..{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string20 = /.{0,1000}pscmd\/serverscript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string21 = /.{0,1000}pscmd\\serverscript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string22 = /.{0,1000}rdp\+kerberos\-password:\/\/.{0,1000}\?dc\=.{0,1000}proxytype.{0,1000}proxyhost.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string23 = /.{0,1000}rdp\+ntlm\-password:\/\/.{0,1000}\@.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string24 = /.{0,1000}sendcmd\(.{0,1000}cmd:PSCMDMessage.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string25 = /.{0,1000}Set\sthe\scorrect\schannel\sname\susing\s\"\"pscmdchannel\"\"\scommand.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string26 = /.{0,1000}skelsec\/evilrdp.{0,1000}/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string27 = /.{0,1000}Starts\sa\sPSCMD\schannel\son\sthe\sremote\send.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
