rule Gotato
{
    meta:
        description = "Detection patterns for the tool 'Gotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string1 = /.{0,1000}\s\-p\s4644\s\-n\smal.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string2 = /.{0,1000}\sProcess\sspawned\swith\sstolen\stoken\!.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string3 = /.{0,1000}\/Gotato\.git.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string4 = /.{0,1000}\/gotato\.go.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string5 = /.{0,1000}\[\+\]\sStole\stoken\sfrom.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string6 = /.{0,1000}\\\\\\\\\.\\\\pipe\\\\mal.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string7 = /.{0,1000}gotato\s\-m\shttp.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string8 = /.{0,1000}gotato\s\-m\spipe.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string9 = /.{0,1000}gotato.{0,1000}\s\-n\smal.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string10 = /.{0,1000}gotato.{0,1000}\s\-p\s4644.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string11 = /.{0,1000}Gotato\-main\..{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string12 = /.{0,1000}httpntlm\.go.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string13 = /.{0,1000}httpntlm\.old.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string14 = /.{0,1000}iammaguire\/Gotato.{0,1000}/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string15 = /.{0,1000}TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
