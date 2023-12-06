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
        $string1 = /\sextract\s\-\-secrets\s\-\-zsh/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string2 = /\.\/Passdetective/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string3 = /\/PassDetective\.git/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string4 = /aydinnyunus\/PassDetective/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string5 = /PassDetective\sextract/ nocase ascii wide
        // Description: PassDetective is a command-line tool that scans shell command history to detect mistakenly written passwords - API keys and secrets
        // Reference: https://github.com/aydinnyunus/PassDetective
        $string6 = /PassDetective\-main\./ nocase ascii wide

    condition:
        any of them
}
