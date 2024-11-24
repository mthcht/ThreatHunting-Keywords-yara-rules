rule koadic
{
    meta:
        description = "Detection patterns for the tool 'koadic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "koadic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string1 = /\sComputerDefaults\.exe/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string2 = /\score\.payload\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string3 = /\score\.stager\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string4 = " impacket" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string5 = " pypykatz" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string6 = /\.\/koadic/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string7 = /\/bitsadmin\/bitsadmin\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string8 = /\/createstager\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string9 = "/enum_domain_info" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string10 = "/exec_psexec" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string11 = "/exec_wmi" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string12 = "/hashdump_dc" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string13 = "/implant/elevate/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string14 = /\/killav\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/zerosum0x0/koadic
        $string15 = "/Koadic" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string16 = /\/koadic\.git/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string17 = "/loot_finder" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string18 = "/manage/exec_cmd" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string19 = "/mimishim/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string20 = /\/mshta\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string21 = /\/mshtajs\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string22 = "/phishing/password_box" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string23 = /\/regsvr\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string24 = /\/rundll32\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string25 = "/rundll32_js" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string26 = "/shellcode_excel" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string27 = /\/stager\/powershell\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string28 = /\/stager\/powershell\/payload\.ps1/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string29 = /\/Tash\.dll/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string30 = /\/TashClient\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string31 = /\/TashLoader\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string32 = /\/wmi\.dropper/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string33 = "AddUserImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string34 = "BitsadminStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string35 = "bypassuac_compdefaults" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string36 = "bypassuac_compmgmtlauncher" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string37 = "bypassuac_eventvwr" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string38 = "bypassuac_fodhelper" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string39 = "bypassuac_sdclt" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string40 = "bypassuac_slui" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string41 = "bypassuac_systempropertiesadvanced" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string42 = "bypassuac_wsreset" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string43 = "cd koadic" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string44 = "ClipboardImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string45 = "cmdshell " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string46 = "comsvcs_lsass" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string47 = "ComsvcsLSASS" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string48 = "DotNet2JSImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string49 = "DownloadFileImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string50 = "EnableRDesktopImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string51 = /enum_domain_info\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string52 = /enum_printers\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string53 = /enum_shares\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string54 = "ExcelReflectImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string55 = "ExecCmdImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string56 = "gather/user_hunter" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string57 = "hashdump_sam" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string58 = "HashDumpDCImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string59 = "HashDumpSAMImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string60 = "implant/elevate/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string61 = "implant/gather/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string62 = "implant/inject/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string63 = "implant/persist/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string64 = "implant/pivot/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string65 = "import Payload" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string66 = "import Stager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string67 = "JScriptStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string68 = /Koadic\.persist/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string69 = /koadic_load\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string70 = /koadic_net\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string71 = /koadic_process\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string72 = /koadic_types\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string73 = /koadic_util\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string74 = "mimikatz_dotnet2js" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string75 = "mimikatz_dynwrapx" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string76 = "mimikatz_tashlib" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string77 = /mimishim\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string78 = "MSHTAStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string79 = "offsecginger/koadic" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string80 = /password_box\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string81 = "PasswordBoxImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string82 = "PowerShellStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string83 = "PsExecLiveImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string84 = /ReflectiveDLLInjection\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string85 = "RegistryImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string86 = "RunDLL32JSStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string87 = "ScanTCPImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string88 = "SchTasksImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string89 = /secretsdump\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string90 = "seriously_nothing_shady_here" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string91 = /set\s.{0,1000}\svirus_scanner/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string92 = "set LFILE /" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string93 = "set zombie " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string94 = "shellcode_dotnet2js" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string95 = "shellcode_dynwrapx" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string96 = "stager/js/bitsadmin " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string97 = "stager/js/disk" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string98 = "stager/js/mshta" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string99 = "stager/js/regsvr " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string100 = "stager/js/rundll32_js " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string101 = "stager/js/wmic " nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string102 = "SWbemServicesImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string103 = "UploadFileImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string104 = "use implant/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string105 = "use stager/" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string106 = "UserHunterImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string107 = /windows_key\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string108 = /wmic\/wmic\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string109 = "WMICStager" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string110 = "WMIPersistImplant" nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string111 = /zerosum0x0.{0,1000}koadic/ nocase ascii wide

    condition:
        any of them
}
