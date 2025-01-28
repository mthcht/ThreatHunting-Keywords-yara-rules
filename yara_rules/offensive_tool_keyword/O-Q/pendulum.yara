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
        $string1 = /\/pendulum\.git/
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string2 = /\/src\/pendulum\.c/
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string3 = /\/src\/pendulum\.h/
        // Description: Linux Sleep Obfuscation
        // Reference: https://github.com/kyleavery/pendulum
        $string4 = "kyleavery/pendulum"

    condition:
        any of them
}
