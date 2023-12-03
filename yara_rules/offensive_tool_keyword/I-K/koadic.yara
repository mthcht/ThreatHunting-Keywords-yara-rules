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
        $string1 = /.{0,1000}\sComputerDefaults\.exe.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string2 = /.{0,1000}\score\.payload\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string3 = /.{0,1000}\score\.stager\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string4 = /.{0,1000}\simpacket.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string5 = /.{0,1000}\spypykatz.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string6 = /.{0,1000}\.\/koadic.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string7 = /.{0,1000}\/bitsadmin\/bitsadmin\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string8 = /.{0,1000}\/createstager\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string9 = /.{0,1000}\/enum_domain_info.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string10 = /.{0,1000}\/exec_psexec.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string11 = /.{0,1000}\/exec_wmi.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string12 = /.{0,1000}\/hashdump_dc.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string13 = /.{0,1000}\/implant\/elevate\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string14 = /.{0,1000}\/js\/stage\.js.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/zerosum0x0/koadic
        $string15 = /.{0,1000}\/Koadic.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string16 = /.{0,1000}\/koadic\.git.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string17 = /.{0,1000}\/loot_finder.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string18 = /.{0,1000}\/manage\/exec_cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string19 = /.{0,1000}\/mimishim\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string20 = /.{0,1000}\/mshta\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string21 = /.{0,1000}\/mshtajs\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string22 = /.{0,1000}\/phishing\/password_box.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string23 = /.{0,1000}\/regsvr\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string24 = /.{0,1000}\/rundll32\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string25 = /.{0,1000}\/rundll32_js.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string26 = /.{0,1000}\/shellcode_excel.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string27 = /.{0,1000}\/stage_wmi.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string28 = /.{0,1000}\/stager\/powershell\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string29 = /.{0,1000}\/stager\/powershell\/payload\.ps1.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string30 = /.{0,1000}\/Tash\.dll.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string31 = /.{0,1000}\/TashClient\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string32 = /.{0,1000}\/TashLoader\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string33 = /.{0,1000}\/wmi\.dropper.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string34 = /.{0,1000}AddUserImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string35 = /.{0,1000}BitsadminStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string36 = /.{0,1000}bypassuac_compdefaults.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string37 = /.{0,1000}bypassuac_compmgmtlauncher.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string38 = /.{0,1000}bypassuac_eventvwr.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string39 = /.{0,1000}bypassuac_fodhelper.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string40 = /.{0,1000}bypassuac_sdclt.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string41 = /.{0,1000}bypassuac_slui.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string42 = /.{0,1000}bypassuac_systempropertiesadvanced.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string43 = /.{0,1000}bypassuac_wsreset.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string44 = /.{0,1000}cd\skoadic.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string45 = /.{0,1000}ClipboardImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string46 = /.{0,1000}cmdshell\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string47 = /.{0,1000}comsvcs_lsass.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string48 = /.{0,1000}ComsvcsLSASS.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string49 = /.{0,1000}DotNet2JSImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string50 = /.{0,1000}DownloadFileImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string51 = /.{0,1000}EnableRDesktopImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string52 = /.{0,1000}enum_domain_info\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string53 = /.{0,1000}enum_printers\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string54 = /.{0,1000}enum_shares\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string55 = /.{0,1000}ExcelReflectImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string56 = /.{0,1000}ExecCmdImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string57 = /.{0,1000}gather\/user_hunter.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string58 = /.{0,1000}hashdump_sam.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string59 = /.{0,1000}HashDumpDCImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string60 = /.{0,1000}HashDumpSAMImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string61 = /.{0,1000}implant\/elevate\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string62 = /.{0,1000}implant\/gather\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string63 = /.{0,1000}implant\/inject\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string64 = /.{0,1000}implant\/persist\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string65 = /.{0,1000}implant\/pivot\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string66 = /.{0,1000}import\sPayload.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string67 = /.{0,1000}import\sStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string68 = /.{0,1000}JScriptStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string69 = /.{0,1000}killav\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string70 = /.{0,1000}Koadic\.persist.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string71 = /.{0,1000}koadic_load\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string72 = /.{0,1000}koadic_net\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string73 = /.{0,1000}koadic_process\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string74 = /.{0,1000}koadic_types\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string75 = /.{0,1000}koadic_util\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string76 = /.{0,1000}mimikatz_dotnet2js.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string77 = /.{0,1000}mimikatz_dynwrapx.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string78 = /.{0,1000}mimikatz_tashlib.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string79 = /.{0,1000}mimishim\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string80 = /.{0,1000}MSHTAStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string81 = /.{0,1000}offsecginger\/koadic.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string82 = /.{0,1000}password_box\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string83 = /.{0,1000}PasswordBoxImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string84 = /.{0,1000}PowerShellStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string85 = /.{0,1000}PsExecLiveImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string86 = /.{0,1000}ReflectiveDLLInjection\..{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string87 = /.{0,1000}RegistryImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string88 = /.{0,1000}RunDLL32JSStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string89 = /.{0,1000}ScanTCPImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string90 = /.{0,1000}SchTasksImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string91 = /.{0,1000}secretsdump\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string92 = /.{0,1000}seriously_nothing_shady_here.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string93 = /.{0,1000}set\s.{0,1000}\svirus_scanner.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string94 = /.{0,1000}set\sLFILE\s\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string95 = /.{0,1000}set\spayload\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string96 = /.{0,1000}set\szombie\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string97 = /.{0,1000}shellcode_dotnet2js.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string98 = /.{0,1000}shellcode_dynwrapx.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string99 = /.{0,1000}stager\/js\/bitsadmin\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string100 = /.{0,1000}stager\/js\/disk.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string101 = /.{0,1000}stager\/js\/mshta.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string102 = /.{0,1000}stager\/js\/regsvr\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string103 = /.{0,1000}stager\/js\/rundll32_js\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string104 = /.{0,1000}stager\/js\/wmic\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string105 = /.{0,1000}SWbemServicesImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string106 = /.{0,1000}UploadFileImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string107 = /.{0,1000}use\simplant\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string108 = /.{0,1000}use\sstager\/.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string109 = /.{0,1000}UserHunterImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string110 = /.{0,1000}windows_key\.py.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string111 = /.{0,1000}wmic\/wmic\.cmd.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string112 = /.{0,1000}WMICStager.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string113 = /.{0,1000}WMIPersistImplant.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string114 = /.{0,1000}zerosum0x0.{0,1000}koadic.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string115 = /set\sCMD\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string116 = /set\sENDPOINT\s.{0,1000}/ nocase ascii wide
        // Description: Koadic. or COM Command & Control. is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript). with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
        // Reference: https://github.com/offsecginger/koadic
        $string117 = /set\ssrvhost\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
