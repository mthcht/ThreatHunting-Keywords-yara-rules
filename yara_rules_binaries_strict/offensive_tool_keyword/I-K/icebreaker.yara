rule icebreaker
{
    meta:
        description = "Detection patterns for the tool 'icebreaker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icebreaker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string1 = /\sicebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string2 = " -oA icebreaker-scan" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string3 = " --password-list " nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string4 = /\s\-\-script\ssmb\-security\-mode.{0,100}smb\-enum\-shares\s/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string5 = /\ssmb\-cmds\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string6 = /\.py.{0,100}found\-users\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string7 = "/DanMcInerney/ridenum"
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string8 = /\/DeathStar\/DeathStar\.py/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string9 = /\/icebreaker\.git/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string10 = /\/icebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string11 = "/lgandx/Responder"
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string12 = "/opt/icebreaker"
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string13 = /\/Responder\/Responder\.conf/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string14 = /\/ridenum\/ridenum\.py/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string15 = /\/shares\-with\-SCF\.txt/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string16 = /\/smb\-cmds\.txt/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string17 = /\/smb\-signing\-disabled\-hosts\.txt/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string18 = /\/theHarvester\.py/
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string19 = "/virtualenvs/icebreaker"
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string20 = /\\icebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string21 = /1mil\-AD\-passwords\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string22 = "byt3bl33d3r/DeathStar" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string23 = "CoreSecurity/impacket/" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string24 = "DanMcInerney/Empire" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string25 = "DanMcInerney/icebreaker" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string26 = "DanMcInerney/theHarvester" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string27 = /found\-passwords\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string28 = /https\:\/\/0\.0\.0\.0\:1337/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string29 = "icebreaker:P@ssword123456" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string30 = /icebreaker\-master\.zip/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string31 = /icebreaker\-scan\.xml/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string32 = "Invoke-Cats -pwds" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string33 = /Invoke\-Cats\.ps1/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string34 = /Invoke\-Pwds\.ps1/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string35 = /logs\/Responder\-Session\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string36 = /logs\/ridenum\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string37 = /logs\/shares\-with\-SCF\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string38 = /logs\/theHarvester\.py\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string39 = "net localgroup administrators icebreaker" nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string40 = "net user /add icebreaker " nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string41 = /ntlmrelayx\.py\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string42 = "sudo tmux new -s icebreaker"
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string43 = /\-\-wordlist\=.{0,100}\-passwords\.txt/ nocase ascii wide
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
