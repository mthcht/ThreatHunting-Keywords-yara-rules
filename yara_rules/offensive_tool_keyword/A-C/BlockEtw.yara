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
        $string1 = /.{0,1000}\/BlockEtw\.git.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string2 = /.{0,1000}blocketw\.bin.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string3 = /.{0,1000}blocketw\.csproj.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string4 = /.{0,1000}blocketw\.exe.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string5 = /.{0,1000}blocketw\.pdb.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string6 = /.{0,1000}BlockEtw\-master.{0,1000}/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string7 = /.{0,1000}Soledge\/BlockEtw.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
