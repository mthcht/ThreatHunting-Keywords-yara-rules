rule BlockEtw
{
    meta:
        description = "Detection patterns for the tool 'BlockEtw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockEtw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string1 = /\/BlockEtw\.git/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string2 = /blocketw\.bin/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string3 = /blocketw\.csproj/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string4 = /blocketw\.exe/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string5 = /blocketw\.pdb/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string6 = /BlockEtw\-master/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string7 = /Soledge\/BlockEtw/ nocase ascii wide

    condition:
        any of them
}
