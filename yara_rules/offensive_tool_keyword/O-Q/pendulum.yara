rule pendulum
{
    meta:
        description = "Detection patterns for the tool 'pendulum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pendulum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string1 = /\/pendulum\.git/ nocase ascii wide
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string2 = /\/src\/pendulum\.c/ nocase ascii wide
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string3 = /\/src\/pendulum\.h/ nocase ascii wide
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string4 = /kyleavery\/pendulum/ nocase ascii wide

    condition:
        any of them
}
