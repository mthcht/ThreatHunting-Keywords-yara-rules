rule havoc
{
    meta:
        description = "Detection patterns for the tool 'havoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "havoc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string1 = /.{0,1000}\sdemon\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string2 = /.{0,1000}\shavoc\-client.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string3 = /.{0,1000}\.\/donut\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string4 = /.{0,1000}\.\/Havoc/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string5 = /.{0,1000}\.\/havoc\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string6 = /.{0,1000}\/Cracked5pider\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string7 = /.{0,1000}\/demon\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string8 = /.{0,1000}\/demon\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string9 = /.{0,1000}\/demon1\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string10 = /.{0,1000}\/demosyscalls\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string11 = /.{0,1000}\/Dialogs\/Payload\.hpp.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string12 = /.{0,1000}\/Havoc\.cpp.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string13 = /.{0,1000}\/Havoc\.qss.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string14 = /.{0,1000}\/Havoc\.rc.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string15 = /.{0,1000}\/Havoc\/data\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string16 = /.{0,1000}\/Havoc\/main\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string17 = /.{0,1000}\/HavocFramework\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string18 = /.{0,1000}\/HavocImages\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string19 = /.{0,1000}\/havoc\-py\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string20 = /.{0,1000}\/implants\/.{0,1000}\/Syscalls\..{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string21 = /.{0,1000}\/Jump\-exec\/Psexec.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string22 = /.{0,1000}\/kerberoast\.c.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string23 = /.{0,1000}\/kerberoast\.h.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string24 = /.{0,1000}\/nanodump\..{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string25 = /.{0,1000}\/payloads\/DllLdr\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string26 = /.{0,1000}\/RemoteOps\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string27 = /.{0,1000}\/scshell\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string28 = /.{0,1000}\/Talon\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string29 = /.{0,1000}\/Talon\/.{0,1000}Agent\/Source.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string30 = /.{0,1000}\/Widgets\/LootWidget\..{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string31 = /.{0,1000}\/WMI\/wmi\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string32 = /.{0,1000}\\demon\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string33 = /.{0,1000}\\demon\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string34 = /.{0,1000}\\demon\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string35 = /.{0,1000}\\demon1\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string36 = /.{0,1000}\\demosyscalls\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string37 = /.{0,1000}\\Ekko\.exe.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string38 = /.{0,1000}40056\/service\-endpoint.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string39 = /.{0,1000}5spider:password1234.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string40 = /.{0,1000}bin\/addusertogroup\.x64.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string41 = /.{0,1000}bin\/setuserpass\.x64.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string42 = /.{0,1000}Delegation\/delegation\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string43 = /.{0,1000}DllLdr\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string44 = /.{0,1000}Domaininfo\/Domaininfo\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string45 = /.{0,1000}dotnet\sinline\-execute\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string46 = /.{0,1000}externalc2\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string47 = /.{0,1000}f5a45c4aa478a7ba9b44654a929bddc2f6453cd8d6f37cd893dda47220ad9870.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string48 = /.{0,1000}havoc\sclient.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string49 = /.{0,1000}havoc\sserver.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string50 = /.{0,1000}havoc\.agent.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string51 = /.{0,1000}Havoc\.git.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string52 = /.{0,1000}Havoc\.hpp.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string53 = /.{0,1000}havoc\.service.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string54 = /.{0,1000}havoc\.yaotl.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string55 = /.{0,1000}Havoc\/Client.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string56 = /.{0,1000}Havoc\/cmd\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string57 = /.{0,1000}Havoc\/payloads.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string58 = /.{0,1000}Havoc\/pkg.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string59 = /.{0,1000}Havoc\/Teamserver.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string60 = /.{0,1000}havoc_agent\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string61 = /.{0,1000}havoc_agent_talon\..{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string62 = /.{0,1000}havoc_default\.yaotl.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string63 = /.{0,1000}havoc_externalc2.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string64 = /.{0,1000}havoc_service_connect.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string65 = /.{0,1000}havoc\-c2\-client.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string66 = /.{0,1000}havoc\-c2\-data.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string67 = /.{0,1000}havocframework\.com.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string68 = /.{0,1000}HavocService.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string69 = /.{0,1000}HavocTalonInteract.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string70 = /.{0,1000}HavocUi\.cpp.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string71 = /.{0,1000}HavocUi\.h.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string72 = /.{0,1000}HavocUI\.hpp.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string73 = /.{0,1000}http.{0,1000}\/demon\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string74 = /.{0,1000}http.{0,1000}\/demon\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string75 = /.{0,1000}implant\.sleep\-obf.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string76 = /.{0,1000}Implant\\SleepMask.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string77 = /.{0,1000}inject\s1337\s\/.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string78 = /.{0,1000}inject\.spawn.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string79 = /.{0,1000}inject\.spoofaddr.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string80 = /.{0,1000}Injection\\Spawn32.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string81 = /.{0,1000}Injection\\Spawn64.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string82 = /.{0,1000}InvokeAssembly\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string83 = /.{0,1000}jump\-exec\spsexec\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string84 = /.{0,1000}nanodump_ppl\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string85 = /.{0,1000}nanodump_ssp\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string86 = /.{0,1000}nanorobeus\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string87 = /.{0,1000}powerpick\.py.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string88 = /.{0,1000}PowerPick\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string89 = /.{0,1000}PowershellRunner\.h.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string90 = /.{0,1000}ServiceHavoc\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string91 = /.{0,1000}set\shavoc\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string92 = /.{0,1000}shellcode\sinject\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string93 = /.{0,1000}shellcode\sspawn\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string94 = /.{0,1000}Shellcode\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string95 = /.{0,1000}token\sfind\-tokens.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string96 = /.{0,1000}token\simpersonate\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string97 = /.{0,1000}token\sprivs\-get.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string98 = /.{0,1000}token\sprivs\-list.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string99 = /.{0,1000}token\ssteal\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string100 = /.{0,1000}x\-ishavocframework.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string101 = /dcenum\s.{0,1000}/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string102 = /powerpick\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
