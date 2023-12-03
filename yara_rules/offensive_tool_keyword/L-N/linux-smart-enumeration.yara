rule linux_smart_enumeration
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string1 = /.{0,1000}\s\$lse_find_opts\s.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string2 = /.{0,1000}\.\/lse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string3 = /.{0,1000}\/etc\/passwd.{0,1000}\/\.sudo_as_admin_successful.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string4 = /.{0,1000}\/linux\-smart\-enumeration\.git.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string5 = /.{0,1000}\/releases\/latest\/download\/lse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string6 = /.{0,1000}adm\|admin\|root\|sudo\|wheel.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string7 = /.{0,1000}bash\slse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string8 = /.{0,1000}chmod\s700\slse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string9 = /.{0,1000}chmod\s755\slse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string10 = /.{0,1000}diego\-treitos\/linux\-smart\-enumeration.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string11 = /.{0,1000}find\s\/\s.{0,1000}\s\-4000\s\-type\sf\s\-print.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string12 = /.{0,1000}find\s\/\s.{0,1000}\s\-perm\s\-2000\s\-type\sf\s\-print.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string13 = /.{0,1000}find\s\/\s.{0,1000}\s\-regextype\segrep\s\-iregex.{0,1000}\\\.kdbx.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string14 = /.{0,1000}https:\/\/.{0,1000}\/releases\/download\/.{0,1000}\/lse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string15 = /.{0,1000}linux\-smart\-enumeration\-master.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string16 = /.{0,1000}lse\.sh\s\-l.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string17 = /.{0,1000}netstat\s\-tnlp\s\|\|\sss\s\-tnlp.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string18 = /.{0,1000}netstat\s\-unlp\s\|\|\sss\s\-unlp.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string19 = /.{0,1000}package_cvs_into_lse\.sh.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string20 = /.{0,1000}ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,1000}127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string21 = /.{0,1000}sudo\s\-nS\sid\'\s\&\&\slse_sudo\=true.{0,1000}/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string22 = /.{0,1000}user\|username\|login\|pass\|password\|pw\|credentials.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
