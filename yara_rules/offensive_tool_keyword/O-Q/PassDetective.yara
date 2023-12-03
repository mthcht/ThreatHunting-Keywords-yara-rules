rule PassDetective
{
    meta:
        description = "Detection patterns for the tool 'PassDetective' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassDetective"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string1 = /.{0,1000}\sextract\s\-\-secrets\s\-\-zsh.{0,1000}/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string2 = /.{0,1000}\.\/Passdetective.{0,1000}/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string3 = /.{0,1000}\/PassDetective\.git.{0,1000}/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string4 = /.{0,1000}aydinnyunus\/PassDetective.{0,1000}/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string5 = /.{0,1000}PassDetective\sextract.{0,1000}/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string6 = /.{0,1000}PassDetective\-main\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
