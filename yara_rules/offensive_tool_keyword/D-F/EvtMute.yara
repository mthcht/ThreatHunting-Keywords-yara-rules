rule EvtMute
{
    meta:
        description = "Detection patterns for the tool 'EvtMute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvtMute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string1 = /\.exe.{0,1000}\s\-\-Filter\s.{0,1000}rule\sdisable\s\{\scondition\:\strue\s\}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string2 = /\/EvtMute\.git/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string3 = /bats3c\/EvtMute/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string4 = /ConvertToShellcode\.py/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string5 = /DQoNCiAgICwuICAgKCAgIC4gICAgICApICAgICAgICAgICAgICAgIiAgICAgICAgICAgICwuICAgKCAgI/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string6 = /EvtMuteHook\.dll/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string7 = /EvtMuteHook\.dll/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string8 = /EvtMuteHook\.iobj/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string9 = /EvtMuteHook\.ipdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string10 = /EvtMuteHook\.pdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string11 = /EvtMuteHook\.sln/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string12 = /EvtMute\-master/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string13 = /JG1lbnUgPSAiIgppZiAoJGZ1bmNpb25lc19wcmV2aWFzLmNvdW50IC1sZSAxKSB/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string14 = /JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKcHVibGl/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string15 = /SharpEvtMute\.cs/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string16 = /SharpEvtMute\.exe/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string17 = /SharpEvtMute\.pdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string18 = /SharpEvtMute\.sln/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string19 = /ShellcodeRDI\.py/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string20 = /YaraFilters.{0,1000}lsassdump\.yar/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string21 = /ZnVuY3Rpb24gRG9udXQtTG9hZGVyIHtwYXJhbSgkcHJvY2Vzc19pZCwkZG9udXRmaWx/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string22 = /ZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string23 = /ZnVuY3Rpb24gSW52b2tlLUJpbmFyeSB7cGFyYW0oJGFyZykKICAgICRoZWxwPUAi/ nocase ascii wide

    condition:
        any of them
}
