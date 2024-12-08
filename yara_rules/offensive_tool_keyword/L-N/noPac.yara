rule noPac
{
    meta:
        description = "Detection patterns for the tool 'noPac' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noPac"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string1 = "/Ridter/noPac" nocase ascii wide
        // Description: command used in the method prerequisites of the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string2 = /AdFind\.exe\s\-sc\sgetacls\s\-sddlfilter\s\s\s.{0,1000}computer.{0,1000}\s\s\-recmute/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string3 = /noPac\..{0,1000}\s\-create\-child/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string4 = /noPac\..{0,1000}\s\-dc\-host\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string5 = /noPac\..{0,1000}\s\-dc\-ip\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string6 = /noPac\..{0,1000}\s\-domain\-netbios/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string7 = /noPac\..{0,1000}\s\-dump/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string8 = /noPac\..{0,1000}\s\-hashes\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string9 = /noPac\..{0,1000}\s\-\-impersonate\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string10 = /noPac\..{0,1000}\s\-just\-dc\-ntlm/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string11 = /noPac\..{0,1000}\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string12 = /noPac\..{0,1000}\s\-new\-name\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string13 = /noPac\..{0,1000}\s\-no\-add\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string14 = /noPac\..{0,1000}\s\-pwd\-last\-set/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string15 = /noPac\..{0,1000}\s\-service\-name\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string16 = /noPac\..{0,1000}\s\-shell/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string17 = /noPac\..{0,1000}\s\-shell\-type\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string18 = /noPac\..{0,1000}\s\-use\-ldap/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string19 = /noPac\.py/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string20 = /python\snoPac\./ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string21 = "Ridter/noPac" nocase ascii wide
        // Description: script used in the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string22 = /S4U2self\.py/ nocase ascii wide
        // Description: script used in the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string23 = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}
