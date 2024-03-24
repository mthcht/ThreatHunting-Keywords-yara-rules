rule ConPtyShell
{
    meta:
        description = "Detection patterns for the tool 'ConPtyShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ConPtyShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string1 = /\sConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string2 = /\$parametersConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string3 = /\/ConPtyShell\// nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string4 = /376713183026ccc822e9c1dead28cc81c7cfa7ad1c88e368ada6c31ce3909a2e/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string5 = /antonioCoco\/ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string6 = /ConPtyShell\.cs/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string7 = /ConPtyShell\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string8 = /ConPtyShell\.git/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string9 = /ConPtyShell\.zip/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string10 = /ConPtyShell\.zip/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string11 = /ConPtyShell_dotnet2\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string12 = /CreatePseudoConsole\sfunction\sfound\!\sSpawning\sa\sfully\sinteractive\sshell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string13 = /CreatePseudoConsole\sfunction\snot\sfound\!\sSpawning\sa\snetcat\-like\sinteractive\sshell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string14 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string15 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string16 = /\-RemoteIp\s.{0,1000}\s\-RemotePort\s.{0,1000}\s\-Rows\s.{0,1000}\s\-Cols\s.{0,1000}\s\-CommandLine\s.{0,1000}\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string17 = /SocketHijacking\./ nocase ascii wide

    condition:
        any of them
}
