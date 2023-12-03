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
        $string1 = /.{0,1000}\sBrutesploit.{0,1000}/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string2 = /.{0,1000}\sMicrosploit\.sh.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string3 = /.{0,1000}\.\/Brutesploit.{0,1000}/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string4 = /.{0,1000}\.\/Microsploit.{0,1000}/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string5 = /.{0,1000}\.\/Vegile.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string6 = /.{0,1000}\/BruteSploit.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string7 = /.{0,1000}\/dirsearch\.py.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string8 = /.{0,1000}\/instabrute\.py.{0,1000}/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string9 = /.{0,1000}\/Vegile\.git.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string10 = /.{0,1000}Brutesploit\.git.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string11 = /.{0,1000}BruteSploit\/wlist\/.{0,1000}/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string12 = /.{0,1000}microsploit\.git.{0,1000}/ nocase ascii wide
        // Description: BruteSploit is a collection of method for automated Generate. Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation.combine.transform and permutation some words or file text
        // Reference: https://github.com/screetsec/BruteSploit
        $string13 = /.{0,1000}Password\-Default\/service\.txt.{0,1000}/ nocase ascii wide
        // Description: Fast and easy create backdoor office exploitation using module metasploit packet . Microsoft Office . Open Office . Macro attack . Buffer Overflow
        // Reference: https://github.com/screetsec/Microsploit
        $string14 = /.{0,1000}screetsec\/Microsploit.{0,1000}/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string15 = /.{0,1000}Vegile\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
