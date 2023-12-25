rule wevtutil
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string1 = /cmd.{0,1000}\swevtutil\.exe\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string2 = /wevtutil\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string3 = /wevtutil\sclear\-log/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string4 = /wevtutil\.exe\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string5 = /wevtutil\.exe\sclear\-log/ nocase ascii wide
        // Description: disable a specific eventlog
        // Reference: N/A
        $string6 = /wevtutil\.exe\ssl\s.{0,1000}\s\/e:false/ nocase ascii wide

    condition:
        any of them
}
