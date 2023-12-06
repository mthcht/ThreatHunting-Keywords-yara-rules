rule nps_payload
{
    meta:
        description = "Detection patterns for the tool 'nps_payload' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nps_payload"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script will generate payloads for basic intrusion detection avoidance
        // Reference: https://github.com/trustedsec/nps_payload
        $string1 = /\/nps_payload\.git/ nocase ascii wide
        // Description: This script will generate payloads for basic intrusion detection avoidance
        // Reference: https://github.com/trustedsec/nps_payload
        $string2 = /msf_payload\.ps1/ nocase ascii wide
        // Description: This script will generate payloads for basic intrusion detection avoidance. It utilizes publicly demonstrated techniques from several different sources.
        // Reference: https://github.com/trustedsec/nps_payload
        $string3 = /nps_payload/ nocase ascii wide
        // Description: This script will generate payloads for basic intrusion detection avoidance
        // Reference: https://github.com/trustedsec/nps_payload
        $string4 = /nps_payload\.py/ nocase ascii wide
        // Description: This script will generate payloads for basic intrusion detection avoidance
        // Reference: https://github.com/trustedsec/nps_payload
        $string5 = /nps_payload\-master/ nocase ascii wide

    condition:
        any of them
}
