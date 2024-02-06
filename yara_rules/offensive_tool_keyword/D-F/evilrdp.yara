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
        $string1 = /\sevilrdp\.gui\s/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string2 = /\/evilrdp\.git/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string3 = /\/evilrdp\// nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string4 = /\\evilrdp\\/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string5 = /aardwolf\.extensions\.RDPEDYC\.vchannels\.socksoverrdp\simport\sSocksOverRDPChannel/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string6 = /aiocmd\\nested_completer\.py/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string7 = /Async\sRDP\sClient\.\sDuckyscript\swill\sbe\sexecuted\sby\spressing\sESC\s3\stimes/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string8 = /do_socksoverrdp\(.{0,1000}127\.0\.0\.1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string9 = /do_socksproxy\(.{0,1000}\slisten_ip\s\=\s\'127\.0\.0\.1\'/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string10 = /do_startpscmd\(.{0,1000}serverscript\.ps1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string11 = /ducky_keyboard_sender\(scancode/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string12 = /Emulates\sa\srightclick\son\sthe\sgiven\scoordinates/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string13 = /evilrdp\.exe/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string14 = /evilrdp\-main/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string15 = /Executes\sa\spowershell\scommand\son\sthe\sremote\shost\.\sRequires\sPSCMD/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string16 = /from\sevilrdp\.consolehelper/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string17 = /import\sEVILRDPConsole/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string18 = /import\sEvilRDPGUI/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string19 = /PSCMD\schannel\swas\seither\snot\sdefined\swhile\sconnecting\sOR\sthe\schannel\sname\sis\snot\sthe\sdefault\./ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string20 = /pscmd\/serverscript\.ps1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string21 = /pscmd\\serverscript\.ps1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string22 = /rdp\+kerberos\-password\:\/\/.{0,1000}\?dc\=.{0,1000}proxytype.{0,1000}proxyhost/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string23 = /rdp\+ntlm\-password\:\/\/.{0,1000}\@/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string24 = /sendcmd\(.{0,1000}cmd\:PSCMDMessage/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string25 = /Set\sthe\scorrect\schannel\sname\susing\s\"\"pscmdchannel\"\"\scommand/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string26 = /skelsec\/evilrdp/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string27 = /Starts\sa\sPSCMD\schannel\son\sthe\sremote\send/ nocase ascii wide

    condition:
        any of them
}
