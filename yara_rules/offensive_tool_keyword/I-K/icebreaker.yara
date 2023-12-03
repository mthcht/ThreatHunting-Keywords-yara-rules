rule icebreaker
{
    meta:
        description = "Detection patterns for the tool 'icebreaker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icebreaker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string1 = /.{0,1000}\sicebreaker\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string2 = /.{0,1000}\s\-oA\sicebreaker\-scan.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string3 = /.{0,1000}\s\-\-password\-list\s.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string4 = /.{0,1000}\s\-\-script\ssmb\-security\-mode.{0,1000}smb\-enum\-shares\s.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string5 = /.{0,1000}\ssmb\-cmds\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string6 = /.{0,1000}\.py.{0,1000}found\-users\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string7 = /.{0,1000}\/DanMcInerney\/ridenum.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string8 = /.{0,1000}\/DeathStar\/DeathStar\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string9 = /.{0,1000}\/icebreaker\.git.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string10 = /.{0,1000}\/icebreaker\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string11 = /.{0,1000}\/lgandx\/Responder.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string12 = /.{0,1000}\/opt\/icebreaker.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string13 = /.{0,1000}\/Responder\/Responder\.conf.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string14 = /.{0,1000}\/ridenum\/ridenum\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string15 = /.{0,1000}\/shares\-with\-SCF\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string16 = /.{0,1000}\/smb\-cmds\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string17 = /.{0,1000}\/smb\-signing\-disabled\-hosts\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string18 = /.{0,1000}\/theHarvester\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string19 = /.{0,1000}\/virtualenvs\/icebreaker.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string20 = /.{0,1000}\\icebreaker\.py.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string21 = /.{0,1000}1mil\-AD\-passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string22 = /.{0,1000}byt3bl33d3r\/DeathStar.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string23 = /.{0,1000}CoreSecurity\/impacket\/.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string24 = /.{0,1000}DanMcInerney\/Empire.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string25 = /.{0,1000}DanMcInerney\/icebreaker.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string26 = /.{0,1000}DanMcInerney\/theHarvester.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string27 = /.{0,1000}found\-passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string28 = /.{0,1000}https:\/\/0\.0\.0\.0:1337.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string29 = /.{0,1000}icebreaker:P\@ssword123456.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string30 = /.{0,1000}icebreaker\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string31 = /.{0,1000}icebreaker\-scan\.xml.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string32 = /.{0,1000}Invoke\-Cats\s\-pwds.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string33 = /.{0,1000}Invoke\-Cats\.ps1.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string34 = /.{0,1000}Invoke\-Pwds\.ps1.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string35 = /.{0,1000}logs\/Responder\-Session\.log.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string36 = /.{0,1000}logs\/ridenum\.log.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string37 = /.{0,1000}logs\/shares\-with\-SCF\.txt.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string38 = /.{0,1000}logs\/theHarvester\.py\.log.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string39 = /.{0,1000}net\slocalgroup\sadministrators\sicebreaker.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string40 = /.{0,1000}net\suser\s\/add\sicebreaker\s.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string41 = /.{0,1000}ntlmrelayx\.py\.log.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string42 = /.{0,1000}sudo\stmux\snew\s\-s\sicebreaker.{0,1000}/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string43 = /.{0,1000}\-\-wordlist\=.{0,1000}\-passwords\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
