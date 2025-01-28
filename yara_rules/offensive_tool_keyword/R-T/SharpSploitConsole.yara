rule SharpSploitConsole
{
    meta:
        description = "Detection patterns for the tool 'SharpSploitConsole' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploitConsole"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string1 = /\/SharpSploit\.dll/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string2 = /\/SharpSploitConsole\.git/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string3 = /\\SharpSploit\.dll/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string4 = /\\SharpSploitConsole\./ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string5 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string6 = "6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string7 = "anthemtotheego/SharpSploitConsole" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string8 = "c12b1320138b4fd7578d7b1b4741bba50f115c8dcf7c3eb3d30bf939de134ade" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string9 = "Executes a chosen Mimikatz command" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string10 = "Executes everything but DCSync - requires admin" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string11 = "Kerberoast -username " nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string12 = "Mimi-Command " nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string13 = "Mimi-Command privilege::" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string14 = "Performs a kerberoasting attack against targeted" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string15 = "Retrieve Domain Cached Credentials hashes from registry" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string16 = "Retrieve LSA secrets stored in registry" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string17 = "Retrieve Wdigest credentials from registry" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string18 = "Runs a powershell command while attempting to bypass AMSI" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string19 = "SharpSploit Command Execution" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string20 = "SharpSploit Credentials Commands" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string21 = "SharpSploit Domain Enumeration Commands" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string22 = "SharpSploit Enumeration Commands" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string23 = "SharpSploit Lateral Movement Commands" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string24 = /SharpSploit\.Enumeration\./ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string25 = /sharpSploitConsole\.exe/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string26 = /SharpSploitConsole\.sln/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string27 = "SharpSploitConsole:>" nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string28 = "SharpSploitConsole-master" nocase ascii wide

    condition:
        any of them
}
