rule shred
{
    meta:
        description = "Detection patterns for the tool 'shred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shred"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: deleting bash history
        // Reference: N/A
        $string1 = /shred\s\$HISTFILE/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string2 = /shred\s\-n\s.{0,1000}\s\-u\s\-z\s.{0,1000}_history/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string3 = /shred\s\-n\s.{0,1000}\s\-z\s\-u\s.{0,1000}_history/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string4 = "shred --remove" nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string5 = /shred\s\-u\s\-n\s.{0,1000}\s\-z\s.{0,1000}_history/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string6 = /shred\s\-u\s\-z\s\-n\s.{0,1000}_history/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string7 = "shred -u" nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string8 = /shred\s\-z\s\-n\s.{0,1000}\s\-u\s.{0,1000}_history/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string9 = /shred\s\-z\s\-u\s\-n\s.{0,1000}_history/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string10 = "shred -z" nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string11 = "shred --zero" nocase ascii wide

    condition:
        any of them
}
