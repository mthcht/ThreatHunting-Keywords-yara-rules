rule Fynloski_Backdoor
{
    meta:
        description = "Detection patterns for the tool 'Fynloski Backdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fynloski Backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string1 = /\#BOT\#CloseServer/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string2 = /\#BOT\#OpenUrl/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string3 = /\#BOT\#RunPrompt/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string4 = /\#BOT\#SvrUninstall/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string5 = /\#BOT\#URLDownload/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string6 = /\#BOT\#URLUpdate/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string7 = /\#GetClipboardText/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string8 = /ActiveOfflineKeylogger/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string9 = /ActiveOnlineKeylogger/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string10 = /ActiveOnlineKeyStrokes/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string11 = /ACTIVEREMOTESHELL/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string12 = /DDOSHTTPFLOOD/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string13 = /DDOSSYNFLOOD/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string14 = /DDOSUDPFLOOD/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string15 = /I\swasn\'t\sable\sto\sopen\sthe\shosts\sfile\,\smaybe\sbecause\sUAC\sis\senabled\sin\sremote\scomputer\!/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string16 = /KILLREMOTESHELL/ nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string17 = /ping\s127\.0\.0\.1\s\-n\s4\s\>\sNUL\s\&\&\s\\"/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
