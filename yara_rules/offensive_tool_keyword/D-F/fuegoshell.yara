rule fuegoshell
{
    meta:
        description = "Detection patterns for the tool 'fuegoshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuegoshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string1 = /\sgenerate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string2 = /\sgenerate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string3 = /\$myC2ipAdress/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string4 = /\$myVictimIPAdress/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string5 = /\/fuegoshell\.git/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string6 = /\/generate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string7 = /\/generate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string8 = /\[\+\]\sNew\sincoming\sshell\sfrom\s\:\s/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string9 = /\\generate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string10 = /\\generate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string11 = /\>\\fuego\-control/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string12 = /\>\\fuego\-data/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string13 = /\>\\fuegoshell/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string14 = /5b64c12376f1ec1b876ede9b84f6883ee5f1ee5065e945dc2115c5e04c02aadf/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string15 = /6c6c37d26619bfe90a84e3e70c8dd45073488e120d239500bef10977f8523073/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string16 = /fuegoShell\-bind\>/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string17 = /Fuegoshell\-client\sstarted/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string18 = /fuegoShell\-reverse\>/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string19 = /Fuegoshell\-server\sstarted/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string20 = /Here\sare\sthe\soneliners\sfor\sreverse\sshell\susing\srpc\snamed\spipes/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string21 = /v1k1ngfr\.github\.io\/fuegoshell\// nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string22 = /v1k1ngfr\/fuegoshell/ nocase ascii wide

    condition:
        any of them
}
