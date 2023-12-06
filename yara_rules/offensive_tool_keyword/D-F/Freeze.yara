rule Freeze
{
    meta:
        description = "Detection patterns for the tool 'Freeze' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string1 = /\s\-encrypt\s.{0,1000}\s\-process\s.{0,1000}\s\-sandbox\s/ nocase ascii wide
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string2 = /\/optiv\/Freeze\// nocase ascii wide
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string3 = /\\freeze\.go/ nocase ascii wide
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string4 = /build\sFreeze\.go/ nocase ascii wide
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string5 = /Freeze_.{0,1000}_darwin_amd64/ nocase ascii wide
        // Description: Freeze is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls. and alternative execution methods
        // Reference: https://github.com/optiv/Freeze
        $string6 = /Freeze_.{0,1000}_linux_amd64/ nocase ascii wide

    condition:
        any of them
}
