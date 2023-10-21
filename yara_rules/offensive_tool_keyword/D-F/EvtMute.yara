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
        $string1 = /\.exe.*\s\-\-Filter\s.*rule\sdisable\s{\scondition:\strue\s}/ nocase ascii wide
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
        $string5 = /EvtMuteHook\.dll/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string6 = /EvtMuteHook\.dll/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string7 = /EvtMuteHook\.iobj/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string8 = /EvtMuteHook\.ipdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string9 = /EvtMuteHook\.pdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string10 = /EvtMuteHook\.sln/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string11 = /EvtMute\-master/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string12 = /SharpEvtMute\.cs/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string13 = /SharpEvtMute\.exe/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string14 = /SharpEvtMute\.pdb/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string15 = /SharpEvtMute\.sln/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string16 = /ShellcodeRDI\.py/ nocase ascii wide
        // Description: This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging - mute the event log
        // Reference: https://github.com/bats3c/EvtMute
        $string17 = /YaraFilters.*lsassdump\.yar/ nocase ascii wide

    condition:
        any of them
}