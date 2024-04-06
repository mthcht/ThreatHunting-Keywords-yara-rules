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
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string2 = /\/code_exec\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string3 = /\/cradle\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string4 = /\/dcshadow\.html/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string5 = /\/evil\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string6 = /\/evilscript\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string7 = /\/exetotext\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string8 = /\/kekeo\.exe/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security. penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string9 = /\/nishang/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string10 = /\/nishang\// nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string11 = /\/Wait_For_Command\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string12 = /\/WindDef_WebInstall\.hta/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string13 = /\\Check\-VM\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string14 = /\\code_exec\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string15 = /\\Copy\-VSS\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string16 = /\\cradle\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string17 = /\\Create\-MultipleSessions\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string18 = /\\dcshadow\.html/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string19 = /\\Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string20 = /\\Download_Execute\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string21 = /\\Download_Execute_PS\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string22 = /\\Download\-Execute\-PS\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string23 = /\\Enable\-DuplicateToken\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string24 = /\\evil\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string25 = /\\evilscript\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string26 = /\\Execute\-DNSTXT\-Code\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string27 = /\\exetotext\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string28 = /\\Get\-PassHints\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string29 = /\\Get\-UnConstrained\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string30 = /\\kekeo\.exe/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string31 = /\\Keylogger\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string32 = /\\persist\.vbs/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string33 = /\\Wait_For_Command\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string34 = /\\WindDef_WebInstall\.hta/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string35 = /Add\-ConstrainedDelegationBackdoor/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string36 = /Add\-Exfiltration\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string37 = /Add\-Persistence\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string38 = /Add\-Persistence\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string39 = /Add\-RegBackdoor\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string40 = /Add\-ScrnSaveBackdoor\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string41 = /Brute\-Force\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string42 = /ConvertTo\-ROT13\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string43 = /ConvertTo\-ROT13\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string44 = /Create\-MultipleSessions\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string45 = /DNS_TXT_Pwnage\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string46 = /Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string47 = /Download_Execute/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string48 = /Download\-Execute\-PS/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string49 = /Enable\-DuplicateToken/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string50 = /Execute\-Command\-MSSQL/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string51 = /Execute\-DNSTXT\-Code/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string52 = /ExetoText\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string53 = /FireBuster\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string54 = /FireListener\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string55 = /Get\-LSASecret/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string56 = /Get\-LSASecret\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string57 = /Get\-LSASecrets\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string58 = /Get\-PassHashes/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string59 = /Get\-PassHashes\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string60 = /Get\-PassHints/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string61 = /Get\-WebCredentials/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string62 = /Get\-WebCredentials\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string63 = /Get\-WLAN\-Keys/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string64 = /Get\-WLAN\-Keys\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string65 = /Get\-Wlan\-Keys\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string66 = /Gupt\-Backdoor\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string67 = /Gupt\-Backdoor\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string68 = /HTTP\-Backdoor\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string69 = /HTTP\-Backdoor\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string70 = /Invoke\-.{0,1000}WDigestDowngrade\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string71 = /Invoke\-ADSBackdoor/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string72 = /Invoke\-ADSBackdoor/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string73 = /Invoke\-AmsiBypass/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string74 = /Invoke\-AmsiBypass/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string75 = /Invoke\-BruteForce/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string76 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string77 = /Invoke\-CredentialsPhish/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string78 = /Invoke\-Interceptor/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string79 = /Invoke\-Interceptor\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string80 = /Invoke\-JSRatRegsvr/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string81 = /Invoke\-JSRatRegsvr/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string82 = /Invoke\-JSRatRundll/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string83 = /Invoke\-JSRatRundll/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string84 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string85 = /Invoke\-MimikatzWDigestDowngrade/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string86 = /Invoke\-Mimikittenz/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string87 = /Invoke\-NetworkRelay/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string88 = /Invoke\-NetworkRelay\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string89 = /Invoke\-PortScan/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string90 = /Invoke\-PoshRatHttp/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string91 = /Invoke\-PoshRatHttp/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string92 = /Invoke\-PoshRatHttps/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string93 = /Invoke\-PoshRatHttps/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string94 = /Invoke\-PowerShellIcmp/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string95 = /Invoke\-PowerShellIcmp\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string96 = /Invoke\-PowerShellTcp/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string97 = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string98 = /Invoke\-PowerShellTcpOneLine/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string99 = /Invoke\-PowerShellTcpOneLine/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string100 = /Invoke\-PowerShellTcpOneLine\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string101 = /Invoke\-PowerShellTcpOneLineBind/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string102 = /Invoke\-PowerShellTcpOneLineBind\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string103 = /Invoke\-PowerShellUdp/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string104 = /Invoke\-PowerShellUdp\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string105 = /Invoke\-PowerShellUdpOneLine/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string106 = /Invoke\-PowerShellUdpOneLine\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string107 = /Invoke\-PowerShellWmi/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string108 = /Invoke\-PowerShellWmi\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string109 = /Invoke\-Prasadhak/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string110 = /Invoke\-Prasadhak\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string111 = /Invoke\-PsGcat/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string112 = /Invoke\-PSGcat\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string113 = /Invoke\-PsGcat\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string114 = /Invoke\-PsGcatAgent/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string115 = /Invoke\-PsGcatAgent\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string116 = /Invoke\-PsUACme/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string117 = /Invoke\-PsUACme\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string118 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string119 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string120 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string121 = /Invoke\-SSIDExfil/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string122 = /Invoke\-SSIDExfil/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string123 = /Keylogger\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string124 = /mimikatz\.exe/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string125 = /nishang\.exe/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string126 = /nishang\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string127 = /nishang\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string128 = /Nishang\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string129 = /nishang\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string130 = /nishang\-0\-3\-4\.html/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string131 = /Out\-DnsTxt\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string132 = /Out\-RundllCommand/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string133 = /Port\-Scan\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string134 = /Powerpreter\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string135 = /Powerpreter\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string136 = /powerpreter\.psm1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string137 = /Prasadhak\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string138 = /Remove\-Persistence\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string139 = /Remove\-Persistence\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string140 = /Remove\-PoshRat/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string141 = /Remove\-PoshRat\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string142 = /Remove\-Update\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string143 = /Run\-EXEonRemote/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string144 = /Run\-EXEonRemote\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string145 = /samratashok\/nishang/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string146 = /Set\-DCShadowPermissions/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string147 = /Set\-DCShadowPermissions/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string148 = /Set\-RemotePSRemoting/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string149 = /Set\-RemotePSRemoting\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string150 = /Set\-RemoteShellAccess\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string151 = /Set\-RemoteWMI\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string152 = /Set\-RemoteWMI\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string153 = /Show\-TargetScreen\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string154 = /Show\-TargetScreen\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string155 = /Start\-CaptureServer\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string156 = /Start\-CaptureServer\.ps1/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string157 = /TexttoExe\.ps1/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string158 = /TGT_backdoor_svc/ nocase ascii wide

    condition:
        any of them
}
