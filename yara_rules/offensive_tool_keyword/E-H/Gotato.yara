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
        $string1 = /\s\-p\s4644\s\-n\smal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string2 = /\sProcess\sspawned\swith\sstolen\stoken\!/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string3 = /\/Gotato\.git/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string4 = /\/gotato\.go/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string5 = /\[\+\]\sStole\stoken\sfrom/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string6 = /\\\\\\\\\.\\\\pipe\\\\mal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string7 = /gotato\s\-m\shttp/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string8 = /gotato\s\-m\spipe/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string9 = /gotato.{0,1000}\s\-n\smal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string10 = /gotato.{0,1000}\s\-p\s4644/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string11 = /Gotato\-main\./ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string12 = /httpntlm\.go/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string13 = /httpntlm\.old/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string14 = /iammaguire\/Gotato/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string15 = /TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA/ nocase ascii wide

    condition:
        any of them
}
