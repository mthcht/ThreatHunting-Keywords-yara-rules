rule nimbo_c2
{
    meta:
        description = "Detection patterns for the tool 'nimbo-c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimbo-c2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string1 = /.{0,1000}\/tmp\/metadata\/na\.elf.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string2 = /.{0,1000}\[\+\]\skeystrokes\sdump\sfrom\sagent.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string3 = /.{0,1000}agent\/dll\.nim.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string4 = /.{0,1000}agent\/elf\.nim.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string5 = /.{0,1000}agent\/exe\.nim.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string6 = /.{0,1000}assembly\s.{0,1000}\.asm\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string7 = /.{0,1000}assembly\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string8 = /.{0,1000}beacon\.elf.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string9 = /.{0,1000}C:\\ProgramData\\Prefetch\\na\.exe.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string10 = /.{0,1000}C2\sFramework\sfor\svillains.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string11 = /.{0,1000}download\s\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string12 = /.{0,1000}dump_lsass.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string13 = /.{0,1000}dump_sam\(.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string14 = /.{0,1000}exit_nimbo.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string15 = /.{0,1000}Itay\sMigdal.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string16 = /.{0,1000}JAB4ACAAPQAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAC0AUABJAEQAIAAkAHAAaQBkACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAG4AYQBtAGUAOwAgACIAJABwAGkAZAAgACQAeAAuAGUAeABlACIA.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string17 = /.{0,1000}KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string18 = /.{0,1000}keylogger\sis\salready\soff.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string19 = /.{0,1000}keylogger\sstopped.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string20 = /.{0,1000}lsass\scomsvcs.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string21 = /.{0,1000}lsass\sdirect.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string22 = /.{0,1000}lsass\sdump\sfrom\sagent.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string23 = /.{0,1000}lsass_.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string24 = /.{0,1000}memfd\simplant\s.{0,1000}\.elf.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string25 = /.{0,1000}memfd\stask\s.{0,1000}\.elf.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string26 = /.{0,1000}nimbo_main.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string27 = /.{0,1000}nimbo_prompt_color.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string28 = /.{0,1000}nimbo_root.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string29 = /.{0,1000}Nimbo\-C2\sw1ll\sr0ck\sy0ur\sw0rld.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string30 = /.{0,1000}Nimbo\-C2.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string31 = /.{0,1000}Nimbo\-C2\..{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string32 = /.{0,1000}nimbo\-dependencies.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string33 = /.{0,1000}persist\srun\s.{0,1000}hkcu.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string34 = /.{0,1000}persist\srun\s.{0,1000}hklm.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string35 = /.{0,1000}persist\sspe\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string36 = /.{0,1000}pstree\.ps1.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string37 = /.{0,1000}reg\.exe\ssave\shklm\\sam.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string38 = /.{0,1000}reg\.exe\ssave\shklm\\security.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string39 = /.{0,1000}reg\.exe\ssave\shklm\\system.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string40 = /.{0,1000}RwBlAHQALQBDAG8AbQBwAHUAdABlAHIASQBuAGYAbwAgAHwAIABzAGUAbABlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVwBpAG4AZABvAHcAcwBQAHIAbwBkAHUAYwB0AE4AYQBtAGUA.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string41 = /.{0,1000}RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAE4AZQB0AHcAbwByAGsAQQBkAGEAcAB0AGUAcgBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEkAUABBAGQAZAByAGUAcwBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAoACQAXwAgAC0AbABpAGsAZQAgACIAMQAwAC4AKgAuACoALgAqACIAKQAgAC0AbwByACAAKAAkAF8AIAAtAGwAaQBrAGUAIAAiADEAOQAyAC4AMQA2ADgALgAqAC4AKgAiACkAIAAtAG8AcgAgACgAJABfACAALQBsAGkAawBlACAAIgAxADcAMgAuADEANgA4AC4AKgAuACoAIgApAH0A.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string42 = /.{0,1000}shellc\s.{0,1000}\.bin\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string43 = /.{0,1000}shellc\s.{0,1000}\.shellc\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string44 = /.{0,1000}uac\sfodhelper\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string45 = /.{0,1000}uac\ssdclt\s.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string46 = /.{0,1000}uac_bypass.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string47 = /.{0,1000}wrap_execute_assembly.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string48 = /.{0,1000}wrap_execute_encoded_powershell.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string49 = /.{0,1000}wrap_get_clipboard.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string50 = /.{0,1000}wrap_inject_shellc.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string51 = /.{0,1000}wrap_load_memfd.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string52 = /.{0,1000}wrap_unhook_ntdll.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string53 = /.{0,1000}WwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBJAGQAZQBuAHQAaQB0AHkAXQA6ADoARwBlAHQAQwB1AHIAcgBlAG4AdAAoACkALgBuAGEAbQBlAAoA.{0,1000}/ nocase ascii wide
        // Description: Nimbo-C2 is yet another (simple and lightweight) C2 framework
        // Reference: https://github.com/itaymigdal/Nimbo-C2
        $string54 = /na\.exe\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
