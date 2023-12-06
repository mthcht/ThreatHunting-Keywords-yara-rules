rule PyExec
{
    meta:
        description = "Detection patterns for the tool 'PyExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string1 = /\sadm2sys\.py/ nocase ascii wide
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string2 = /\/adm2sys\.py/ nocase ascii wide
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string3 = /\/PyExec\.git/ nocase ascii wide
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string4 = /\\adm2sys\.py/ nocase ascii wide
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string5 = /OlivierLaflamme\/PyExec/ nocase ascii wide
        // Description: This is a very simple privilege escalation technique from admin to System. This is the same technique PSExec uses.
        // Reference: https://github.com/OlivierLaflamme/PyExec
        $string6 = /PyExec\-main\./ nocase ascii wide

    condition:
        any of them
}
