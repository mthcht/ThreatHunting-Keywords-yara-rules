rule RogueWinRM
{
    meta:
        description = "Detection patterns for the tool 'RogueWinRM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueWinRM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string1 = /\/RogueWinRM\.git/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string2 = /\\RogueWinRM\.sln/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string3 = /\\RogueWinRM\\/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string4 = /\\windows\\temp\\nc64\.exe/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string5 = /antonioCoco\/RogueWinRM/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string6 = /B03A3AF9\-9448\-43FE\-8CEE\-5A2C43BFAC86/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string7 = /ec260817672bcc48f734f89e9eac84ebc7903924b36f807caf58c6820c0e336c/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string8 = /RogueWinRM\s/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string9 = /RogueWinRM\.cpp/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string10 = /RogueWinRM\.exe/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string11 = /RogueWinRM\.zip/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string12 = /WinRM\salready\srunning\son\sport\s5985\.\sUnexploitable\!/ nocase ascii wide

    condition:
        any of them
}
