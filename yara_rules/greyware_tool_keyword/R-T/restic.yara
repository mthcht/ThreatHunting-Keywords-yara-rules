rule restic
{
    meta:
        description = "Detection patterns for the tool 'restic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "restic"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string1 = /\s\-r\srclone\:.{0,1000}\sinit/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string2 = /\srestic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string3 = /\srestic\/restic\s/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string4 = /\/restic\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string5 = /\/restic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string6 = /\/restic_.{0,1000}_windows_amd64\.zip/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string7 = /\/restic\-master\// nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string8 = /\\restic\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string9 = /\\restic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string10 = /\\RESTIC_.{0,1000}_WINDOWS_AMD64\.E\-FC5783E7\.pf/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string11 = /\\restic_.{0,1000}_windows_amd64\.zip/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string12 = /\\restic\-completion\.ps1/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string13 = /\\restic\-master\\/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string14 = /78312276c42ff12162e5afaf6de8586d432022c8bc7551366471b8812703be7e/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string15 = /98394683d8f30ce9fb313100f593dc16e97a52723b18d534cf586391a97cdc1d/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string16 = /restic\scheck\s\-\-read\-data/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string17 = /restic\sinit\s\-\-repo\s/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string18 = /restic\s\-o\ss3\.bucket\-lookup/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string19 = /restic\s\-r\s/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string20 = /restic\/restic\:latest/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string21 = /restic_.{0,1000}_windows_amd64\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string22 = /RESTIC_REST_PASSWORD/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string23 = /RESTIC_REST_USERNAME/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string24 = /winpty\srestic\s/ nocase ascii wide

    condition:
        any of them
}
