rule shred
{
    meta:
        description = "Detection patterns for the tool 'shred' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shred"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string1 = /.{0,1000}shred\s\-\-remove.{0,1000}/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string2 = /.{0,1000}shred\s\-u.{0,1000}/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string3 = /.{0,1000}shred\s\-z.{0,1000}/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string4 = /.{0,1000}shred\s\-\-zero.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
