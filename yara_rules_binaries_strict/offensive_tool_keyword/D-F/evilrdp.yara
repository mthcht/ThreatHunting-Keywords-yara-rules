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
        $string3 = "/evilrdp/" nocase ascii wide
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
        $string8 = /do_socksoverrdp\(.{0,100}127\.0\.0\.1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string9 = /do_socksproxy\(.{0,100}\slisten_ip\s\=\s\'127\.0\.0\.1\'/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string10 = /do_startpscmd\(.{0,100}serverscript\.ps1/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string11 = /ducky_keyboard_sender\(scancode/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string12 = "Emulates a rightclick on the given coordinates" nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string13 = /evilrdp\.exe/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string14 = "evilrdp-main" nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string15 = /Executes\sa\spowershell\scommand\son\sthe\sremote\shost\.\sRequires\sPSCMD/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string16 = /from\sevilrdp\.consolehelper/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string17 = "import EVILRDPConsole" nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string18 = "import EvilRDPGUI" nocase ascii wide
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
        $string22 = /rdp\+kerberos\-password\:\/\/.{0,100}\?dc\=.{0,100}proxytype.{0,100}proxyhost/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string23 = /rdp\+ntlm\-password\:\/\/.{0,100}\@/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string24 = /sendcmd\(.{0,100}cmd\:PSCMDMessage/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string25 = "Set the correct channel name using \"\"pscmdchannel\"\" command" nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string26 = "skelsec/evilrdp" nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string27 = "Starts a PSCMD channel on the remote end" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
