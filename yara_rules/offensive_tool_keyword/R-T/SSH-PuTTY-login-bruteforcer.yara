rule SSH_PuTTY_login_bruteforcer
{
    meta:
        description = "Detection patterns for the tool 'SSH-PuTTY-login-bruteforcer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-PuTTY-login-bruteforcer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Turn PuTTY into an SSH login bruteforcing tool.
        // Reference: https://github.com/InfosecMatter/SSH-PuTTY-login-bruteforcer
        $string1 = /ssh\-putty\-brute\s\-/ nocase ascii wide
        // Description: Turn PuTTY into an SSH login bruteforcing tool.
        // Reference: https://github.com/InfosecMatter/SSH-PuTTY-login-bruteforcer
        $string2 = /ssh\-putty\-brute\.ps1/ nocase ascii wide
        // Description: Turn PuTTY into an SSH login bruteforcing tool.
        // Reference: https://github.com/InfosecMatter/SSH-PuTTY-login-bruteforcer
        $string3 = /SSH\-PuTTY\-login\-bruteforcer/ nocase ascii wide

    condition:
        any of them
}
