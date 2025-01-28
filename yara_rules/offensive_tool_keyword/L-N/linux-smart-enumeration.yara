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
        $string1 = /\s\$lse_find_opts\s/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string2 = /\.\/lse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string3 = /\/etc\/passwd.{0,1000}\/\.sudo_as_admin_successful/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string4 = /\/linux\-smart\-enumeration\.git/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string5 = /\/releases\/latest\/download\/lse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string6 = /adm\|admin\|root\|sudo\|wheel/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string7 = /bash\slse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string8 = /chmod\s700\slse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string9 = /chmod\s755\slse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string10 = "diego-treitos/linux-smart-enumeration"
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string11 = /find\s\/\s.{0,1000}\s\-4000\s\-type\sf\s\-print/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string12 = /find\s\/\s.{0,1000}\s\-perm\s\-2000\s\-type\sf\s\-print/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string13 = /find\s\/\s.{0,1000}\s\-regextype\segrep\s\-iregex.{0,1000}\\\.kdbx/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string14 = /https\:\/\/.{0,1000}\/releases\/download\/.{0,1000}\/lse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string15 = "linux-smart-enumeration-master"
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string16 = /lse\.sh\s\-l/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string17 = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string18 = /netstat\s\-unlp\s\|\|\sss\s\-unlp/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string19 = /package_cvs_into_lse\.sh/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string20 = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,1000}127\.0\.0\.1/
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string21 = "sudo -nS id' && lse_sudo=true"
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string22 = /user\|username\|login\|pass\|password\|pw\|credentials/

    condition:
        any of them
}
