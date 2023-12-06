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
        $string2 = /\/ConPtyShell\// nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string3 = /antonioCoco\/ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string4 = /ConPtyShell\.cs/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string5 = /ConPtyShell\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string6 = /ConPtyShell\.zip/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string7 = /ConPtyShell_dotnet2\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string8 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string9 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string10 = /\-RemoteIp\s.{0,1000}\s\-RemotePort\s.{0,1000}\s\-Rows\s.{0,1000}\s\-Cols\s.{0,1000}\s\-CommandLine\s.{0,1000}\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string11 = /SocketHijacking\./ nocase ascii wide

    condition:
        any of them
}
