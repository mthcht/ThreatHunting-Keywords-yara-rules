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
        $string1 = /.{0,1000}\/antak\.aspx.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string2 = /.{0,1000}\/code_exec\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string3 = /.{0,1000}\/cradle\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string4 = /.{0,1000}\/dcshadow\.html.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string5 = /.{0,1000}\/evil\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string6 = /.{0,1000}\/evilscript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string7 = /.{0,1000}\/exetotext\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string8 = /.{0,1000}\/kekeo\.exe.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security. penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string9 = /.{0,1000}\/nishang.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string10 = /.{0,1000}\/nishang\/.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string11 = /.{0,1000}\/Wait_For_Command\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string12 = /.{0,1000}\/WindDef_WebInstall\.hta.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string13 = /.{0,1000}\\Check\-VM\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string14 = /.{0,1000}\\code_exec\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string15 = /.{0,1000}\\Copy\-VSS\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string16 = /.{0,1000}\\cradle\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string17 = /.{0,1000}\\Create\-MultipleSessions\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string18 = /.{0,1000}\\dcshadow\.html.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string19 = /.{0,1000}\\Do\-Exfiltration\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string20 = /.{0,1000}\\Download_Execute\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string21 = /.{0,1000}\\Download_Execute_PS\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string22 = /.{0,1000}\\Download\-Execute\-PS\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string23 = /.{0,1000}\\Enable\-DuplicateToken\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string24 = /.{0,1000}\\evil\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string25 = /.{0,1000}\\evilscript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string26 = /.{0,1000}\\Execute\-DNSTXT\-Code\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string27 = /.{0,1000}\\exetotext\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string28 = /.{0,1000}\\Get\-PassHints\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string29 = /.{0,1000}\\Get\-UnConstrained\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string30 = /.{0,1000}\\kekeo\.exe.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string31 = /.{0,1000}\\Keylogger\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string32 = /.{0,1000}\\persist\.vbs.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string33 = /.{0,1000}\\Wait_For_Command\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string34 = /.{0,1000}\\WindDef_WebInstall\.hta.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string35 = /.{0,1000}Add\-ConstrainedDelegationBackdoor.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string36 = /.{0,1000}Add\-Exfiltration\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string37 = /.{0,1000}Add\-Persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string38 = /.{0,1000}Add\-Persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string39 = /.{0,1000}Add\-RegBackdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string40 = /.{0,1000}Add\-ScrnSaveBackdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string41 = /.{0,1000}Brute\-Force\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string42 = /.{0,1000}ConvertTo\-ROT13\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string43 = /.{0,1000}ConvertTo\-ROT13\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string44 = /.{0,1000}Create\-MultipleSessions\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string45 = /.{0,1000}DNS_TXT_Pwnage\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string46 = /.{0,1000}Do\-Exfiltration\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string47 = /.{0,1000}Download_Execute.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string48 = /.{0,1000}Download\-Execute\-PS.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string49 = /.{0,1000}Enable\-DuplicateToken.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string50 = /.{0,1000}Execute\-Command\-MSSQL.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string51 = /.{0,1000}Execute\-DNSTXT\-Code.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string52 = /.{0,1000}ExetoText\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string53 = /.{0,1000}FireBuster\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string54 = /.{0,1000}FireListener\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string55 = /.{0,1000}Get\-LSASecret.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string56 = /.{0,1000}Get\-LSASecret\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string57 = /.{0,1000}Get\-LSASecrets\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string58 = /.{0,1000}Get\-PassHashes.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string59 = /.{0,1000}Get\-PassHashes\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string60 = /.{0,1000}Get\-PassHints.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string61 = /.{0,1000}Get\-WebCredentials.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string62 = /.{0,1000}Get\-WebCredentials\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string63 = /.{0,1000}Get\-WLAN\-Keys.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string64 = /.{0,1000}Get\-WLAN\-Keys\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string65 = /.{0,1000}Get\-Wlan\-Keys\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string66 = /.{0,1000}Gupt\-Backdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string67 = /.{0,1000}Gupt\-Backdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string68 = /.{0,1000}HTTP\-Backdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string69 = /.{0,1000}HTTP\-Backdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string70 = /.{0,1000}Invoke\-.{0,1000}WDigestDowngrade\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string71 = /.{0,1000}Invoke\-ADSBackdoor.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string72 = /.{0,1000}Invoke\-ADSBackdoor.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string73 = /.{0,1000}Invoke\-AmsiBypass.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string74 = /.{0,1000}Invoke\-AmsiBypass.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string75 = /.{0,1000}Invoke\-BruteForce.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string76 = /.{0,1000}Invoke\-ConPtyShell.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string77 = /.{0,1000}Invoke\-CredentialsPhish.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string78 = /.{0,1000}Invoke\-Interceptor.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string79 = /.{0,1000}Invoke\-Interceptor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string80 = /.{0,1000}Invoke\-JSRatRegsvr.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string81 = /.{0,1000}Invoke\-JSRatRegsvr.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string82 = /.{0,1000}Invoke\-JSRatRundll.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string83 = /.{0,1000}Invoke\-JSRatRundll.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string84 = /.{0,1000}Invoke\-Mimikatz.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string85 = /.{0,1000}Invoke\-MimikatzWDigestDowngrade.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string86 = /.{0,1000}Invoke\-Mimikittenz.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string87 = /.{0,1000}Invoke\-NetworkRelay.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string88 = /.{0,1000}Invoke\-NetworkRelay\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string89 = /.{0,1000}Invoke\-PortScan.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string90 = /.{0,1000}Invoke\-PoshRatHttp.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string91 = /.{0,1000}Invoke\-PoshRatHttp.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string92 = /.{0,1000}Invoke\-PoshRatHttps.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string93 = /.{0,1000}Invoke\-PoshRatHttps.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string94 = /.{0,1000}Invoke\-PowerShellIcmp.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string95 = /.{0,1000}Invoke\-PowerShellIcmp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string96 = /.{0,1000}Invoke\-PowerShellTcp.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string97 = /.{0,1000}Invoke\-PowerShellTcp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string98 = /.{0,1000}Invoke\-PowerShellTcpOneLine.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string99 = /.{0,1000}Invoke\-PowerShellTcpOneLine.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string100 = /.{0,1000}Invoke\-PowerShellTcpOneLine\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string101 = /.{0,1000}Invoke\-PowerShellTcpOneLineBind.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string102 = /.{0,1000}Invoke\-PowerShellTcpOneLineBind\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string103 = /.{0,1000}Invoke\-PowerShellUdp.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string104 = /.{0,1000}Invoke\-PowerShellUdp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string105 = /.{0,1000}Invoke\-PowerShellUdpOneLine.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string106 = /.{0,1000}Invoke\-PowerShellUdpOneLine\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string107 = /.{0,1000}Invoke\-PowerShellWmi.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string108 = /.{0,1000}Invoke\-PowerShellWmi\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string109 = /.{0,1000}Invoke\-Prasadhak.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string110 = /.{0,1000}Invoke\-Prasadhak\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string111 = /.{0,1000}Invoke\-PsGcat.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string112 = /.{0,1000}Invoke\-PSGcat\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string113 = /.{0,1000}Invoke\-PsGcat\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string114 = /.{0,1000}Invoke\-PsGcatAgent.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string115 = /.{0,1000}Invoke\-PsGcatAgent\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string116 = /.{0,1000}Invoke\-PsUACme.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string117 = /.{0,1000}Invoke\-PsUACme\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string118 = /.{0,1000}Invoke\-SessionGopher.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string119 = /.{0,1000}Invoke\-SessionGopher.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string120 = /.{0,1000}Invoke\-Shellcode\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string121 = /.{0,1000}Invoke\-SSIDExfil.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string122 = /.{0,1000}Invoke\-SSIDExfil.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string123 = /.{0,1000}Keylogger\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string124 = /.{0,1000}mimikatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string125 = /.{0,1000}nishang\.exe.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string126 = /.{0,1000}nishang\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string127 = /.{0,1000}Nishang\.psm1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string128 = /.{0,1000}nishang\.psm1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string129 = /.{0,1000}nishang\.psm1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string130 = /.{0,1000}nishang\-0\-3\-4\.html.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string131 = /.{0,1000}Out\-DnsTxt\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string132 = /.{0,1000}Out\-RundllCommand.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string133 = /.{0,1000}Port\-Scan\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string134 = /.{0,1000}Powerpreter\.psm1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string135 = /.{0,1000}powerpreter\.psm1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string136 = /.{0,1000}Powerpreter\.psm1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string137 = /.{0,1000}Prasadhak\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string138 = /.{0,1000}Remove\-Persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string139 = /.{0,1000}Remove\-Persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string140 = /.{0,1000}Remove\-PoshRat.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string141 = /.{0,1000}Remove\-PoshRat\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string142 = /.{0,1000}Remove\-Update\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string143 = /.{0,1000}Run\-EXEonRemote.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string144 = /.{0,1000}Run\-EXEonRemote\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string145 = /.{0,1000}samratashok\/nishang.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string146 = /.{0,1000}Set\-DCShadowPermissions.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string147 = /.{0,1000}Set\-DCShadowPermissions.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string148 = /.{0,1000}Set\-RemotePSRemoting.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string149 = /.{0,1000}Set\-RemotePSRemoting\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string150 = /.{0,1000}Set\-RemoteShellAccess\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string151 = /.{0,1000}Set\-RemoteWMI\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string152 = /.{0,1000}Set\-RemoteWMI\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string153 = /.{0,1000}Show\-TargetScreen\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string154 = /.{0,1000}Show\-TargetScreen\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string155 = /.{0,1000}Start\-CaptureServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string156 = /.{0,1000}Start\-CaptureServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
        // Reference: https://github.com/samratashok/nishang
        $string157 = /.{0,1000}TexttoExe\.ps1.{0,1000}/ nocase ascii wide
        // Description: Antak is a webshell written in ASP.Net which utilizes PowerShell. Antak is a part of Nishang and updates can be found here: https://github.com/samratashok/nishang
        // Reference: https://github.com/samratashok/nishang/tree/master/Antak-WebShell
        $string158 = /.{0,1000}TGT_backdoor_svc.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
