rule Telemetry
{
    meta:
        description = "Detection patterns for the tool 'Telemetry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Telemetry"
        rule_category = "signature_keyword"

    strings:
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string1 = /Hacktool\.Msil\.Telemetry/ nocase ascii wide

    condition:
        any of them
}
