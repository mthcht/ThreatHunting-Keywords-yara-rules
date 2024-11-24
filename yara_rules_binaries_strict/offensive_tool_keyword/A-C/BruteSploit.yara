rule BruteSploit
{
    meta:
        description = "Detection patterns for the tool 'BruteSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BruteSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string1 = " Brutesploit" nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string2 = /\sMicrosploit\.sh/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string3 = /\.\/Brutesploit/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string4 = /\.\/Microsploit/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string5 = /\.\/Vegile/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string6 = "/BruteSploit" nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string7 = /\/dirsearch\.py/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string8 = /\/instabrute\.py/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string9 = /\/Vegile\.git/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string10 = /Brutesploit\.git/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string11 = "BruteSploit/wlist/" nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string12 = /microsploit\.git/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string13 = /Password\-Default\/service\.txt/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string14 = "screetsec/Microsploit" nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string15 = "Vegile -" nocase ascii wide
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
