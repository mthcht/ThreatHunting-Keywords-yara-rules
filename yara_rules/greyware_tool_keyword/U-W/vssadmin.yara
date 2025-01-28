rule vssadmin
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string1 = /\.exe\sdelete\sshadows/ nocase ascii wide
        // Description: the command is used to create a new Volume Shadow Copy for a specific volume which can be utilized by an attacker to collect data from the local system
        // Reference: N/A
        $string2 = "vssadmin create shadow /for=C:" nocase ascii wide
        // Description: the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3 = /vssadmin\screate\sshadow\s\/for\=C\:.{0,1000}\s\\Temp\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: executes a command to delete the targeted PC volume shadow copies so victims cannot restore older unencrypted versions of their files
        // Reference: https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
        $string4 = "vssadmin delete shadows /all /quiet" nocase ascii wide
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string5 = "vssadmin delete shadows" nocase ascii wide
        // Description: List shadow copies using vssadmin
        // Reference: N/A
        $string6 = "vssadmin list shadows" nocase ascii wide
        // Description: Deletes all Volume Shadow Copies from the system quietly (without prompts).
        // Reference: N/A
        $string7 = /vssadmin.{0,1000}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
        // Description: the command is used to create a new Volume Shadow Copy for a specific volume which can be utilized by an attacker to collect data from the local system
        // Reference: N/A
        $string8 = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide

    condition:
        any of them
}
