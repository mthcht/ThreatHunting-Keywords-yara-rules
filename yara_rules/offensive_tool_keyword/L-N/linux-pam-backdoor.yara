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
        $string1 = /\.\/backdoor\.sh\s/ nocase ascii wide
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string2 = /\/linux\-pam\-backdoor\.git/ nocase ascii wide
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string3 = /backdoor\.sh\s\-v\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string4 = /linux\-pam\-backdoor\-master/ nocase ascii wide
        // Description: Linux PAM Backdoor
        // Reference: https://github.com/zephrax/linux-pam-backdoor
        $string5 = /zephrax\/linux\-pam\-backdoor/ nocase ascii wide

    condition:
        any of them
}
