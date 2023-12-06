rule crond
{
    meta:
        description = "Detection patterns for the tool 'crond' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crond"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Masquerading as Linux Crond Process.Masquerading occurs when the name or location of an executable* legitimate or malicious. is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_masquerading_crond.yml
        $string1 = /cp\s\-i\s\/bin\/sh\s.{0,1000}\/crond/ nocase ascii wide

    condition:
        any of them
}
