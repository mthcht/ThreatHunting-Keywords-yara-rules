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
        $string1 = /.{0,1000}ssh\-putty\-brute\s\-.{0,1000}/ nocase ascii wide
        // Description: Turn PuTTY into an SSH login bruteforcing tool.
        // Reference: https://github.com/InfosecMatter/SSH-PuTTY-login-bruteforcer
        $string2 = /.{0,1000}ssh\-putty\-brute\.ps1.{0,1000}/ nocase ascii wide
        // Description: Turn PuTTY into an SSH login bruteforcing tool.
        // Reference: https://github.com/InfosecMatter/SSH-PuTTY-login-bruteforcer
        $string3 = /.{0,1000}SSH\-PuTTY\-login\-bruteforcer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
