rule nishang
{
    meta:
        description = "Detection patterns for the tool 'nishang' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nishang"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string1 = /\/antak\.aspx/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security. penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string2 = /\/nishang/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string3 = /\/nishang\// nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string4 = /Add\-ConstrainedDelegationBackdoor/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string5 = /Add\-Exfiltration\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string6 = /Add\-Persistence\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string7 = /ConvertTo\-ROT13\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string8 = /Create\-MultipleSessions\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string9 = /Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string10 = /Download_Execute/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string11 = /Download\-Execute\-PS/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string12 = /Enable\-DuplicateToken/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string13 = /Execute\-Command\-MSSQL/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string14 = /Execute\-DNSTXT\-Code/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string15 = /ExetoText\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string16 = /FireBuster\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string17 = /FireListener\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string18 = /Get\-LSASecret/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string19 = /Get\-PassHashes/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string20 = /Get\-PassHints/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string21 = /Get\-WebCredentials/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string22 = /Get\-WLAN\-Keys/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string23 = /Gupt\-Backdoor\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string24 = /HTTP\-Backdoor\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string25 = /Invoke\-.*WDigestDowngrade\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string26 = /Invoke\-ADSBackdoor/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string27 = /Invoke\-AmsiBypass/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string28 = /Invoke\-BruteForce/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string29 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string30 = /Invoke\-CredentialsPhish/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string31 = /Invoke\-Interceptor/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string32 = /Invoke\-JSRatRegsvr/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string33 = /Invoke\-JSRatRundll/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string34 = /Invoke\-NetworkRelay/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string35 = /Invoke\-PortScan/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string36 = /Invoke\-PoshRatHttp/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string37 = /Invoke\-PoshRatHttps/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string38 = /Invoke\-PowerShellIcmp/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string39 = /Invoke\-PowerShellTcp/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string40 = /Invoke\-PowerShellTcpOneLine/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string41 = /Invoke\-PowerShellTcpOneLineBind/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string42 = /Invoke\-PowerShellUdp/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string43 = /Invoke\-PowerShellUdpOneLine/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string44 = /Invoke\-PowerShellWmi/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string45 = /Invoke\-Prasadhak/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string46 = /Invoke\-PsGcat/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string47 = /Invoke\-PsGcatAgent/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string48 = /Invoke\-PsUACme/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string49 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string50 = /Invoke\-SSIDExfil/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string51 = /Keylogger\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string52 = /nishang\.exe/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string53 = /nishang\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string54 = /nishang\.psm1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string55 = /Out\-DnsTxt\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string56 = /Out\-RundllCommand/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string57 = /Powerpreter\.psm1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string58 = /Remove\-Persistence\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string59 = /Remove\-PoshRat/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string60 = /Remove\-Update\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string61 = /Run\-EXEonRemote/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string62 = /samratashok\/nishang/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string63 = /Set\-DCShadowPermissions/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string64 = /Set\-RemotePSRemoting/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string65 = /Set\-RemoteWMI\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string66 = /Show\-TargetScreen\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string67 = /Start\-CaptureServer\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string68 = /TexttoExe\.ps1/ nocase ascii wide

    condition:
        any of them
}