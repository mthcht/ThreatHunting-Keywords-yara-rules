rule windows_defender_remover
{
    meta:
        description = "Detection patterns for the tool 'windows-defender-remover' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-defender-remover"
        rule_category = "signature_keyword"

    strings:
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string1 = /\/WinREG\.KillAV/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string2 = /REG\/KillAV\.A/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string3 = "Win32/DefenderRmv" nocase ascii wide

    condition:
        any of them
}
