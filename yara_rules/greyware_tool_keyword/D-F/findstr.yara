rule findstr
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /dir\s\/a\sC\:\\pagefile\.sys\s\|\sfindstr\s\/R\s/ nocase ascii wide
        // Description: linux commands abused by attackers - gpp finder
        // Reference: N/A
        $string2 = /findstr\s.{0,1000}cpassword\s.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3 = /findstr\s.{0,1000}vnc\.ini/ nocase ascii wide
        // Description: Find GPP Passwords in SYSVOL - search for occurrences of the term "cpassword" in all XML files within the SYSVOL directory of the domain controller - The "cpassword" string refers to a weakly encrypted password stored in some Group Policy Preferences (GPP) files
        // Reference: N/A
        $string4 = /findstr\s\/S\scpassword\s\$env\:.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: Find GPP Passwords in SYSVOL - search for occurrences of the term "cpassword" in all XML files within the SYSVOL directory of the domain controller - The "cpassword" string refers to a weakly encrypted password stored in some Group Policy Preferences (GPP) files
        // Reference: N/A
        $string5 = /findstr\s\/S\scpassword\s\%.{0,1000}\%\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string6 = /findstr\s\/si\ssecret\s.{0,1000}\.docx/ nocase ascii wide

    condition:
        any of them
}
