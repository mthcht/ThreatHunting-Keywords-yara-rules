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
        $string4 = /\simpacket/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string5 = /\spypykatz/ nocase ascii wide
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
        $string9 = /\/enum_domain_info/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string10 = /\/exec_psexec/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string11 = /\/exec_wmi/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string12 = /\/hashdump_dc/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string13 = /\/implant\/elevate\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string14 = /\/js\/stage\.js/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/zerosum0x0/koadic
        $string15 = /\/Koadic/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string16 = /\/koadic\.git/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string17 = /\/loot_finder/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string18 = /\/manage\/exec_cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string19 = /\/mimishim\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string20 = /\/mshta\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string21 = /\/mshtajs\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string22 = /\/phishing\/password_box/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string23 = /\/regsvr\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string24 = /\/rundll32\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string25 = /\/rundll32_js/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string26 = /\/shellcode_excel/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string27 = /\/stage_wmi/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string28 = /\/stager\/powershell\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string29 = /\/stager\/powershell\/payload\.ps1/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string30 = /\/Tash\.dll/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string31 = /\/TashClient\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string32 = /\/TashLoader\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string33 = /\/wmi\.dropper/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string34 = /AddUserImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string35 = /BitsadminStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string36 = /bypassuac_compdefaults/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string37 = /bypassuac_compmgmtlauncher/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string38 = /bypassuac_eventvwr/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string39 = /bypassuac_fodhelper/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string40 = /bypassuac_sdclt/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string41 = /bypassuac_slui/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string42 = /bypassuac_systempropertiesadvanced/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string43 = /bypassuac_wsreset/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string44 = /cd\skoadic/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string45 = /ClipboardImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string46 = /cmdshell\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string47 = /comsvcs_lsass/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string48 = /ComsvcsLSASS/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string49 = /DotNet2JSImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string50 = /DownloadFileImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string51 = /EnableRDesktopImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string52 = /enum_domain_info\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string53 = /enum_printers\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string54 = /enum_shares\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string55 = /ExcelReflectImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string56 = /ExecCmdImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string57 = /gather\/user_hunter/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string58 = /hashdump_sam/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string59 = /HashDumpDCImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string60 = /HashDumpSAMImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string61 = /implant\/elevate\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string62 = /implant\/gather\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string63 = /implant\/inject\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string64 = /implant\/persist\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string65 = /implant\/pivot\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string66 = /import\sPayload/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string67 = /import\sStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string68 = /JScriptStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string69 = /killav\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string70 = /Koadic\.persist/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string71 = /koadic_load\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string72 = /koadic_net\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string73 = /koadic_process\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string74 = /koadic_types\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string75 = /koadic_util\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string76 = /mimikatz_dotnet2js/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string77 = /mimikatz_dynwrapx/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string78 = /mimikatz_tashlib/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string79 = /mimishim\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string80 = /MSHTAStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string81 = /offsecginger\/koadic/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string82 = /password_box\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string83 = /PasswordBoxImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string84 = /PowerShellStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string85 = /PsExecLiveImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string86 = /ReflectiveDLLInjection\./ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string87 = /RegistryImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string88 = /RunDLL32JSStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string89 = /ScanTCPImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string90 = /SchTasksImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string91 = /secretsdump\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string92 = /seriously_nothing_shady_here/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string93 = /set\s.{0,1000}\svirus_scanner/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string94 = /set\sLFILE\s\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string95 = /set\spayload\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string96 = /set\szombie\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string97 = /shellcode_dotnet2js/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string98 = /shellcode_dynwrapx/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string99 = /stager\/js\/bitsadmin\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string100 = /stager\/js\/disk/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string101 = /stager\/js\/mshta/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string102 = /stager\/js\/regsvr\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string103 = /stager\/js\/rundll32_js\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string104 = /stager\/js\/wmic\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string105 = /SWbemServicesImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string106 = /UploadFileImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string107 = /use\simplant\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string108 = /use\sstager\// nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string109 = /UserHunterImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string110 = /windows_key\.py/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string111 = /wmic\/wmic\.cmd/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string112 = /WMICStager/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string113 = /WMIPersistImplant/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string114 = /zerosum0x0.{0,1000}koadic/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string115 = /set\sCMD\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string116 = /set\sENDPOINT\s/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string117 = /set\ssrvhost\s/ nocase ascii wide

    condition:
        any of them
}
