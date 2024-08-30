rule shellsilo
{
    meta:
        description = "Detection patterns for the tool 'shellsilo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shellsilo"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string1 = /\sshellsilo\.py/ nocase ascii wide
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string2 = /\/shellsilo\.git/ nocase ascii wide
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string3 = /\/shellsilo\.py/ nocase ascii wide
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string4 = /\\shellsilo\.py/ nocase ascii wide
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string5 = /05f9e54b0f6e0e143de11f98094e43643acaf17e01e0f7387388dc6d91681322/ nocase ascii wide
        // Description: cutting-edge tool that translates C syntax into syscall assembly and its corresponding shellcode
        // Reference: https://github.com/nixpal/shellsilo
        $string6 = /nixpal\/shellsilo/ nocase ascii wide

    condition:
        any of them
}
