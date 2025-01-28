rule linux_pam_backdoor
{
    meta:
        description = "Detection patterns for the tool 'linux-pam-backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-pam-backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string1 = /\.\/backdoor\.sh\s/
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string2 = /\/linux\-pam\-backdoor\.git/
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string3 = /backdoor\.sh\s\-v\s.{0,1000}\s\-p\s/
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string4 = "linux-pam-backdoor-master"
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string5 = "zephrax/linux-pam-backdoor"

    condition:
        any of them
}
