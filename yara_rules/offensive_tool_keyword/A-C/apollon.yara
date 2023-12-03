rule apollon
{
    meta:
        description = "Detection patterns for the tool 'apollon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apollon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string1 = /.{0,1000}\/apollon\-all\-x64.{0,1000}/ nocase ascii wide
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string2 = /.{0,1000}\/apollon\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string3 = /.{0,1000}\/apollon\-selective\-x64.{0,1000}/ nocase ascii wide
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string4 = /.{0,1000}\[\-\]\sSeems\slike\swe\skilled\sauditd\.\sOoopsie\s:D.{0,1000}/ nocase ascii wide
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string5 = /.{0,1000}\[\+\]\sauditd\spatched\ssuccessfully.{0,1000}/ nocase ascii wide
        // Description: evade auditd by writing /proc/PID/mem
        // Reference: https://github.com/codewhitesec/apollon
        $string6 = /.{0,1000}codewhitesec\/apollon.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
