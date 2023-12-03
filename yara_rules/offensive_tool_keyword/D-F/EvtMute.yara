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
        $string1 = /.{0,1000}\.exe.{0,1000}\s\-\-Filter\s.{0,1000}rule\sdisable\s{\scondition:\strue\s}.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string2 = /.{0,1000}\/EvtMute\.git.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string3 = /.{0,1000}bats3c\/EvtMute.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string4 = /.{0,1000}ConvertToShellcode\.py.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string5 = /.{0,1000}DQoNCiAgICwuICAgKCAgIC4gICAgICApICAgICAgICAgICAgICAgIiAgICAgICAgICAgICwuICAgKCAgI.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string6 = /.{0,1000}EvtMuteHook\.dll.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string7 = /.{0,1000}EvtMuteHook\.dll.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string8 = /.{0,1000}EvtMuteHook\.iobj.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string9 = /.{0,1000}EvtMuteHook\.ipdb.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string10 = /.{0,1000}EvtMuteHook\.pdb.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string11 = /.{0,1000}EvtMuteHook\.sln.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string12 = /.{0,1000}EvtMute\-master.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string13 = /.{0,1000}JG1lbnUgPSAiIgppZiAoJGZ1bmNpb25lc19wcmV2aWFzLmNvdW50IC1sZSAxKSB.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string14 = /.{0,1000}JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKcHVibGl.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string15 = /.{0,1000}SharpEvtMute\.cs.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string16 = /.{0,1000}SharpEvtMute\.exe.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string17 = /.{0,1000}SharpEvtMute\.pdb.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string18 = /.{0,1000}SharpEvtMute\.sln.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string19 = /.{0,1000}ShellcodeRDI\.py.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string20 = /.{0,1000}YaraFilters.{0,1000}lsassdump\.yar.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string21 = /.{0,1000}ZnVuY3Rpb24gRG9udXQtTG9hZGVyIHtwYXJhbSgkcHJvY2Vzc19pZCwkZG9udXRmaWx.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string22 = /.{0,1000}ZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y.{0,1000}/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string23 = /.{0,1000}ZnVuY3Rpb24gSW52b2tlLUJpbmFyeSB7cGFyYW0oJGFyZykKICAgICRoZWxwPUAi.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
