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
        $string1 = /\sBrutesploit/ nocase ascii wide
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
        $string6 = /\/BruteSploit/ nocase ascii wide
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
        $string11 = /BruteSploit\/wlist\// nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string12 = /microsploit\.git/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string13 = /Password\-Default\/service\.txt/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string14 = /screetsec\/Microsploit/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string15 = /Vegile\s\-/ nocase ascii wide

    condition:
        any of them
}
