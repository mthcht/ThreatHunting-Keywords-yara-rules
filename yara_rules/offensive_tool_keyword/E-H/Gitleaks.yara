rule Gitleaks
{
    meta:
        description = "Detection patterns for the tool 'Gitleaks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gitleaks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gitleaks is a SAST tool for detecting hardcoded secrets like passwords. api keys. and tokens in git repos. Gitleaks aims to be the easy-to-use. all-in-one solution for finding secrets. past or present. in your code.
        // Reference: https://github.com/zricethezav/gitleaks
        $string1 = /gitleaks/ nocase ascii wide

    condition:
        any of them
}
