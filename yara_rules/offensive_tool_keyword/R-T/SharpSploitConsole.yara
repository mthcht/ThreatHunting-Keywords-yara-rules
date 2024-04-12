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
        $string5 = /3787435B\-8352\-4BD8\-A1C6\-E5A1B73921F4/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string6 = /6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string7 = /anthemtotheego\/SharpSploitConsole/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string8 = /c12b1320138b4fd7578d7b1b4741bba50f115c8dcf7c3eb3d30bf939de134ade/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string9 = /Executes\sa\schosen\sMimikatz\scommand/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string10 = /Executes\severything\sbut\sDCSync\s\-\srequires\sadmin/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string11 = /Kerberoast\s\-username\s/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string12 = /Mimi\-Command\s/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string13 = /Mimi\-Command\sprivilege\:\:/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string14 = /Performs\sa\skerberoasting\sattack\sagainst\stargeted/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string15 = /Retrieve\sDomain\sCached\sCredentials\shashes\sfrom\sregistry/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string16 = /Retrieve\sLSA\ssecrets\sstored\sin\sregistry/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string17 = /Retrieve\sWdigest\scredentials\sfrom\sregistry/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string18 = /Runs\sa\spowershell\scommand\swhile\sattempting\sto\sbypass\sAMSI/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string19 = /SharpSploit\sCommand\sExecution/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string20 = /SharpSploit\sCredentials\sCommands/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string21 = /SharpSploit\sDomain\sEnumeration\sCommands/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string22 = /SharpSploit\sEnumeration\sCommands/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string23 = /SharpSploit\sLateral\sMovement\sCommands/ nocase ascii wide
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
        $string27 = /SharpSploitConsole\:\>/ nocase ascii wide
        // Description: Console Application designed to interact with SharpSploit
        // Reference: https://github.com/anthemtotheego/SharpSploitConsole
        $string28 = /SharpSploitConsole\-master/ nocase ascii wide

    condition:
        any of them
}
