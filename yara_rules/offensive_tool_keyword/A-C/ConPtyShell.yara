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
        $string1 = /.{0,1000}\sConPtyShell.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string2 = /.{0,1000}\/ConPtyShell\/.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string3 = /.{0,1000}antonioCoco\/ConPtyShell.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string4 = /.{0,1000}ConPtyShell\.cs.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string5 = /.{0,1000}ConPtyShell\.exe.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string6 = /.{0,1000}ConPtyShell\.zip.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string7 = /.{0,1000}ConPtyShell_dotnet2\.exe.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string8 = /.{0,1000}Invoke\-ConPtyShell.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string9 = /.{0,1000}Invoke\-ConPtyShell\.ps1.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string10 = /.{0,1000}\-RemoteIp\s.{0,1000}\s\-RemotePort\s.{0,1000}\s\-Rows\s.{0,1000}\s\-Cols\s.{0,1000}\s\-CommandLine\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string11 = /.{0,1000}SocketHijacking\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
