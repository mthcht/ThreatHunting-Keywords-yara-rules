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
        $string1 = /\s\$lse_find_opts\s/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string2 = /\.\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string3 = /\/etc\/passwd.{0,1000}\/\.sudo_as_admin_successful/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string4 = /\/linux\-smart\-enumeration\.git/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string5 = /\/releases\/latest\/download\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string6 = /adm\|admin\|root\|sudo\|wheel/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string7 = /bash\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string8 = /chmod\s700\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string9 = /chmod\s755\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string10 = /diego\-treitos\/linux\-smart\-enumeration/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string11 = /find\s\/\s.{0,1000}\s\-4000\s\-type\sf\s\-print/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string12 = /find\s\/\s.{0,1000}\s\-perm\s\-2000\s\-type\sf\s\-print/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string13 = /find\s\/\s.{0,1000}\s\-regextype\segrep\s\-iregex.{0,1000}\\\.kdbx/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string14 = /https\:\/\/.{0,1000}\/releases\/download\/.{0,1000}\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string15 = /linux\-smart\-enumeration\-master/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string16 = /lse\.sh\s\-l/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string17 = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string18 = /netstat\s\-unlp\s\|\|\sss\s\-unlp/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string19 = /package_cvs_into_lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string20 = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,1000}127\.0\.0\.1/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string21 = /sudo\s\-nS\sid\'\s\&\&\slse_sudo\=true/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string22 = /user\|username\|login\|pass\|password\|pw\|credentials/ nocase ascii wide

    condition:
        any of them
}
