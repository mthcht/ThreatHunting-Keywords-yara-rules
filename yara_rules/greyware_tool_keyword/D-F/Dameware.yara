rule Dameware
{
    meta:
        description = "Detection patterns for the tool 'Dameware' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dameware"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string1 = /\s\/monitor\s\/from_service\s\/cpu_memory_refresh\s.{0,1000}\s\/disk_space_refresh\s.{0,1000}\s\/proc_list_refresh\s.{0,1000}\s\/semkey\s/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string2 = /\s\/r\s\/proxy\s\s\/proxyport\s\s\/proxyusername\s\s\/proxypasswd\s/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string3 = /\s\/register\s\s\/proxy\s\s\/proxyport\s\s\/proxyusername\s\s\/proxypasswd/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string4 = /\s\-a\stcrmtshellagentmodule_/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string5 = /\sDameware\sMini\sRemote\sControl\sx64\s\-\-\sInstallation\scompleted\ssuccessfully/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string6 = /\s\-log\-level\strace\s\-dre\s\-log\-path\s/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string7 = /\stkc_agent_dre\.deb/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string8 = /\.exe\s\-\-pn\sdre_video_uploader\s\-\-logpath\slogs/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string9 = /\.mspa\.n\-able\.com/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string10 = /\/damewareagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string11 = /\/DWMRC_St_64\.msi/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string12 = /\/DWRCC\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string13 = /\/DWRCCMD\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string14 = /\/DWRCS\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string15 = /\/SolarWinds\-Dameware\-DRS\-St\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string16 = /\/tkc_agent_dre\.deb/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string17 = /\\appdata\\local\\damewa\~1\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string18 = /\\appdata\\local\\dameware\sremote\severywhere/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string19 = /\\appdata\\local\\microsoft\\windows\\inetcache\\ie\\can_install_pc\[1\]\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string20 = /\\AppData\\Roaming\\DameWare\sDevelopment\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string21 = /\\baconsoleapp\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string22 = /\\baconsoleappen\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string23 = /\\baseclient\.exe.{0,1000}\s\-consoleinstallcomplete/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string24 = /\\basupclphlp\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string25 = /\\basupclpprg\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string26 = /\\basupconhelper\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string27 = /\\basuplib\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string28 = /\\basupportexpresssrvcupdater_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string29 = /\\basupportexpressstandaloneservice_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string30 = /\\basupregedithlpr\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string31 = /\\basupregedithlpr_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string32 = /\\basupsrvc\.cfg/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string33 = /\\basupsrvc\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string34 = /\\basupsrvc\.ico/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string35 = /\\basupsrvc\.ini/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string36 = /\\basupsrvc\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string37 = /\\basupsrvc_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string38 = /\\basupsrvccnfg\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string39 = /\\basupsrvccnfg_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string40 = /\\basupsrvccnfg_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string41 = /\\basupsrvccnfgde\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string42 = /\\basupsrvccnfgen\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string43 = /\\basupsrvccnfges\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string44 = /\\basupsrvccnfgfr\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string45 = /\\basupsrvccnfgit\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string46 = /\\basupsrvccnfgpt\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string47 = /\\basupsrvcde\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string48 = /\\basupsrvcen\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string49 = /\\basupsrvces\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string50 = /\\basupsrvcevnt3\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string51 = /\\basupsrvcfr\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string52 = /\\basupsrvcit\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string53 = /\\basupsrvcpt\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string54 = /\\basupsrvcupdater\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string55 = /\\basupsrvcupdater_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string56 = /\\basupsysinf.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string57 = /\\basupsysinf\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string58 = /\\basupsysinf\.ini/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string59 = /\\basupsysshell\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string60 = /\\basupsysshell64\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string61 = /\\basuptshelper\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string62 = /\\basuptshelper_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string63 = /\\basuptshelperlib\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string64 = /\\basupunelev\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string65 = /\\basupvista\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string66 = /\\bavideochat\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string67 = /\\bawhook\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string68 = /\\beanywhere\ssupport\sexpress\sservice\s\-\s\[dameware\]/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string69 = /\\currentversion\\uninstall\\dameware\sremote\severywhere/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string70 = /\\DameWare\sDevelopment\\MrcVerbLog/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string71 = /\\Dameware\sMini\sRemote\sControl\sx64\\/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string72 = /\\dameware\smini\sremote\scontrol\sx64\\/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string73 = /\\DameWare\sMini\sRemote\sControl.{0,1000}\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string74 = /\\Dameware\sMini\sRemote\sControl\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string75 = /\\dameware\sremote\severywhere\sagent/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string76 = /\\dameware\sremote\severywhere\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string77 = /\\Dameware\sRemote\sSupport\s\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string78 = /\\Dameware\sRemote\sSupport\\/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string79 = /\\DameWare\.Diagnostics/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string80 = /\\DameWare\.LogAdjuster\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string81 = /\\DameWare\.LogAdjuster\.exe\.config/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string82 = /\\damewareagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string83 = /\\damewareagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string84 = /\\damewareremoteeverywhere\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string85 = /\\damewareremoteeverywhereagentinstaller\.install\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string86 = /\\disable\sdameware\sremote\severywhere\sagent\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string87 = /\\DMRC\-10\-Evaluation\.lic/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string88 = /\\DNTU\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string89 = /\\dre_mac_console\.zip/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string90 = /\\DWAMTD\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string91 = /\\DWAMTDRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string92 = /\\DWMRC_St_64\.msi/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string93 = /\\DWMSISET\.W32/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string94 = /\\DWMSISET\.X64/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string95 = /\\DWNativeWCFClient\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string96 = /\\DWNativeWCFClientRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string97 = /\\DWPing\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string98 = /\\DWPINGRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string99 = /\\DWRCBA\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string100 = /\\DWRCBN\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string101 = /\\DWRCC\.chm/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string102 = /\\DWRCC\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string103 = /\\DWRCC\.log/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string104 = /\\DWRCC\.log/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string105 = /\\DWRCC\.Logging\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string106 = /\\DWRCCH\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string107 = /\\DWRCChat\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string108 = /\\DWRCChatRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string109 = /\\DWRCCMD\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string110 = /\\DWRCCRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string111 = /\\DWRCCSFTv2\.data/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string112 = /\\DWRCD\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string113 = /\\DWRCD\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string114 = /\\DWRCK\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string115 = /\\DWRCOP\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string116 = /\\DWRCOPRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string117 = /\\DWRCPN\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string118 = /\\DWRCRSA\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string119 = /\\DWRCRSS\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string120 = /\\DWRCRSS\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string121 = /\\DWRCS\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string122 = /\\DWRCS\.Logging\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string123 = /\\DWRCS\.reg/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string124 = /\\DWRCSET\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string125 = /\\DWRCSETRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string126 = /\\DWRCSh\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string127 = /\\DWRCSHRegister\.cmd/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string128 = /\\DWRCSI\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string129 = /\\DWRCSI\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string130 = /\\DWRCSIRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string131 = /\\DWRCSMSI\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string132 = /\\DWRCSMSIRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string133 = /\\DWRCSPC\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string134 = /\\DWRCSPCRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string135 = /\\DWRCSPX\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string136 = /\\DWRCSPXRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string137 = /\\DWRCSRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string138 = /\\DWRCST\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string139 = /\\DWRCST\.Logging\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string140 = /\\DWRCSTRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string141 = /\\DWRCU3\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string142 = /\\DWRCWHD\.Logging\.xml/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string143 = /\\DWRCWHDAPI\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string144 = /\\DWRCWHDUI\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string145 = /\\DWRCWHDUIRES\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string146 = /\\DWRCWol\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string147 = /\\DWRCWXL\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string148 = /\\DWRTD\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string149 = /\\DWRTDE\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string150 = /\\DWRTDR\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string151 = /\\DWRTDR\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string152 = /\\DWSGRWRP\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string153 = /\\DWUtil\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string154 = /\\DWWFDS\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string155 = /\\enable\sdameware\sremote\severywhere\sagent\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string156 = /\\eventlog\\application\\dameware\s/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string157 = /\\getsupportservice_common_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string158 = /\\getsupportservice_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string159 = /\\getsupportservice_dameware\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string160 = /\\linuxconsole_dw\s\(1\)\.zip/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string161 = /\\logs\\baseclient_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string162 = /\\logs\\baseconsoleapp_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string163 = /\\logs\\basupclphlp_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string164 = /\\Logs\\DNTU\.log/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string165 = /\\Mini\sRemote\sControl\sClient\sAgent\sMSI\sBuilder\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string166 = /\\Mini\sRemote\sControl\sDiagnostics\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string167 = /\\Mini\sRemote\sControl\sHelp\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string168 = /\\Mini\sRemote\sControl\sLog\sAdjuster\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string169 = /\\Mini\sRemote\sControl\sService/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string170 = /\\Mini\sRemote\sControl\sService\\Settings\\SFT\:\sUpload\sFolder/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string171 = /\\Mini\sRemote\sControl\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string172 = /\\MRC_12\.0_Bootstrap_Install_Log\.txt/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string173 = /\\MRCCv2\.db/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string174 = /\\mspacredentialprovider_.{0,1000}_dameware\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string175 = /\\msparegedithelper_/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string176 = /\\mspxtshlpsrv_/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string177 = /\\mspxwebcom\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string178 = /\\multiplicar\snegocios\\beanywhere\ssupport\sexpress/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string179 = /\\prefetch\\baconsoleapp\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string180 = /\\prefetch\\baseclient\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string181 = /\\prefetch\\basupclphlp\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string182 = /\\prefetch\\basupregedithlpr\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string183 = /\\prefetch\\basupsrvc\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string184 = /\\prefetch\\basupsrvccnfg\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string185 = /\\prefetch\\basupsrvcupdater\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string186 = /\\prefetch\\basupsysinf\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string187 = /\\prefetch\\basuptshelper\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string188 = /\\prefetch\\damewareagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string189 = /\\prefetch\\damewareremoteeverywhereconso/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string190 = /\\prefetch\\tcrmtshellagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string191 = /\\prefetch\\tcrmtshellviewer\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string192 = /\\prefetch\\tkcuploader\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string193 = /\\progra\~2\\damewa\~1\\remoteshell\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string194 = /\\quick\slaunch\\dameware\sremote\severywhere\stech\sconsole\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string195 = /\\Service\sInstall\sOverwrite\sRemote\sCFG/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string196 = /\\SFT\:\sEnable\sSimple\sFile\sTransfer/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string197 = /\\SolarWinds\.DepInjectedClassWalker\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string198 = /\\SolarWinds\.Diags\.Contract\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string199 = /\\SolarWinds\.Diags\.DameWare\.Extensions\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string200 = /\\SolarWinds\.Diags\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string201 = /\\SolarWinds\.Diags\.exe\.config/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string202 = /\\SolarWinds\.Diags\.Extensions\.Common\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string203 = /\\SolarWinds\.Diags\.Extensions\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string204 = /\\SolarWinds\.Diags\.Platform\.Extensions\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string205 = /\\SolarWinds\.Diags\.Strings\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string206 = /\\SOLARWINDS\.DRS\.LICENSOR\.EXE\-/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string207 = /\\SolarWinds\.LicenseManager\.msi/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string208 = /\\SolarWinds\.Licensing\.Gen4\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string209 = /\\SolarWinds\.Licensing\.Gen4\.dll\.config/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string210 = /\\SolarWinds\.Licensing\.Gen4\.Resources\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string211 = /\\SolarWinds\.Licensing\.Gen4\.UI\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string212 = /\\SolarWinds\.Licensing\.MRC\.COMWrapper\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string213 = /\\SolarWinds\.Licensing\.MRC\.COMWrapper\.dll\.config/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string214 = /\\SolarWinds\.Licensing\.MRC\.COMWrapper\.tlb/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string215 = /\\SolarWinds\.Logging\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string216 = /\\SolarWinds\.MRC\.Licensor\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string217 = /\\SolarWinds\.MRC\.Licensor\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string218 = /\\SolarWinds\.MRC\.Licensor\.exe\.config/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string219 = /\\SolarWinds\.MRC\.Licensor\.log/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string220 = /\\SolarWinds\.Pluggability\.Contract\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string221 = /\\SolarWinds\.Pluggability\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string222 = /\\SolarWinds\\Dameware\sMini\sRemote\sControl/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string223 = /\\SolarWinds\\Logs\\Dameware/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string224 = /\\SOLARWINDS\-DAMEWARE\-DRS\-ST\.EX\-/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string225 = /\\SolarWinds\-Dameware\-DRS\-St\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string226 = /\\start\sdameware\sremote\severywhere\sagent\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string227 = /\\start\smenu\\programs\\dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string228 = /\\tcdirectchat\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string229 = /\\tcdirectchatde\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string230 = /\\tcdirectchaten\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string231 = /\\tcdirectchates\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string232 = /\\tcdirectchatfr\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string233 = /\\tcdirectchatit\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string234 = /\\tcdirectchatpt\.dll/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string235 = /\\tcrmtshellagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string236 = /\\tcrmtshellagent_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string237 = /\\tcrmtshellagentmodule_/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string238 = /\\tcrmtshellviewer\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string239 = /\\tcrmtshellviewer_.{0,1000}\.log/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string240 = /\\tcrmtshellviewermodule_/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string241 = /\\tkcuploader\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string242 = /\\wow6432node\\multiplicar\snegocios\\bace_dameware/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string243 = /\<data\>dameware\sremote\severywhere\<\/data\>/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string244 = /\<data\>n\-able\stake\scontrol\<\/data\>/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string245 = /\<provider\sname\=\"dameware\sremote\severywhere\s\-\s\[dameware\]\"\s\/\>/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string246 = /admin\..{0,1000}\.swi\-dre\.com/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string247 = /C\:\\Program\sFiles\\SolarWinds\\Dameware\sMini\sRemote\sControl\sx64\\/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string248 = /C\:\\Users\\mthcht\\AppData\\Roaming\\DameWare\sDevelopment\\/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string249 = /chat\.us\.n\-able\.com/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string250 = /\'company\'\>n\-able\stake\scontrol\<\/data\>/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string251 = /comserver\.corporate\.beanywhere\.com/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string252 = /DameWare\sDevelopment\sCommon\sData\\Mini\sRemote\sControl/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string253 = /DameWare\sDevelopment\\Agent\sConfiguration/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string254 = /dameware\sremote\severywhere\sagent\s\-\s\[dameware\]/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string255 = /DameWare\sRemote\sSupport\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string256 = /damewareagent\.msi/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string257 = /damewareremoteeverywhereagent\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string258 = /damewareremoteeverywhereconsole\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string259 = /\'Description\'\>Dameware\sproducts\<\/Data\>/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string260 = /download\.global\.mspa\.n\-able\.com\// nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string261 = /getsupportservice_common_dameware\\logs/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string262 = /https\:\/\/downloads\.solarwinds\.com\/solarwinds\/Release\/DameWare\// nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string263 = /login\.swi\-dre\.com/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string264 = /msi\-installs\.swi\-rc\.com\// nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string265 = /notifications\..{0,1000}\.swi\-rc\.com/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string266 = /product\:\sdamewareagent\s\-\-/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string267 = /provider\sname\=\"n\-able\stake\scontrol\s\-\s\[dameware\]\"\s\/\>/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string268 = /\-\-single\-argument\shttps\:\/\/www\.solarwinds\.com\/.{0,1000}\/remote\-support\-software/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string269 = /SolarWinds\.MRC\.Licensor/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string270 = /SolarWinds\.Orion\.MaintDateCheck/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string271 = /SolarWinds\-Dameware\-DRS\-St\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string272 = /SolarWinds\-Dameware\-DRS\-St\-Eval\.zip/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string273 = /SolarWinds\-Dameware\-MRC\-32bit\-St\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string274 = /SolarWinds\-Dameware\-MRC\-32bit\-St\-Eval\.zip/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string275 = /SolarWinds\-Dameware\-MRC\-64bit\-St\.exe/ nocase ascii wide
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string276 = /SolarWinds\-Dameware\-MRC\-64bit\-St\-Eval\.zip/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string277 = /stop\sdameware\sremote\severywhere\sagent\.lnk/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string278 = /techws\..{0,1000}\.swi\-rc\.com/ nocase ascii wide
        // Description: Solarwind Dameware Remote Control utilities
        // Reference: https://www.solarwinds.com/fr/remote-support-software
        $string279 = /vaults\..{0,1000}\.swi\-rc\.com/ nocase ascii wide

    condition:
        any of them
}
