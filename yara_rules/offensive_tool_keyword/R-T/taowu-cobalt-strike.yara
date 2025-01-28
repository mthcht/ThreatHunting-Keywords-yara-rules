rule taowu_cobalt_strike
{
    meta:
        description = "Detection patterns for the tool 'taowu-cobalt-strike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "taowu-cobalt-strike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string1 = " Retrieving NTLM Hashes without Touching LSASS" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string2 = /\sto\sdump\sthe\smasterkeys\son\sthe\scurrent\smachine\sfrom\slsass\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string3 = /\/add\-admin\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string4 = /\/aggressor\/spoolsystem\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string5 = /\/ATPMiniDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string6 = /\/blocketw\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string7 = /\/BrowserGhost\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string8 = /\/brute\sforce\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string9 = /\/BypassAddUser\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string10 = /\/ClearnEventRecordID\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string11 = /\/ClearnIpAddress\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string12 = /\/ClearnTempLog\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string13 = /\/credential\saccess\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string14 = /\/CredPhisher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string15 = /\/cve\-2014\-4113\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string16 = /\/cve\-2014\-4113\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string17 = /\/cve\-2015\-1701\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string18 = /\/cve\-2015\-1701\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string19 = /\/cve\-2016\-0051\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string20 = /\/CVE\-2020\-0796\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string21 = /\/CVE\-2021\-1675\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string22 = /\/dazzleUP_Reflective_DLL\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string23 = /\/DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string24 = /\/DecryptTeamViewer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string25 = /\/dis_defender\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string26 = /\/EfsPotato\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string27 = /\/EncryptedZIP\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string28 = /\/FakeLogonScreen\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string29 = /\/frpc\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string30 = /\/fscan\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string31 = /\/FullPowers\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string32 = /\/Gopher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string33 = /\/hack\-browser\-data\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string34 = /\/InternalMonologue\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string35 = /\/Intranet\spenetration\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string36 = /\/Invoke\-EternalBlue\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string37 = /\/Invoke\-MS16032\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string38 = /\/Invoke\-MS16135\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string39 = /\/JuicyPotato\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string40 = /\/JuicyPotato\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string41 = /\/KillEvenlogService\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string42 = /\/Ladon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string43 = /\/Ladon1\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string44 = /\/Lateral\smovement\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string45 = /\/lazagne\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string46 = /\/ListAllUsers\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string47 = /\/ListLogged\-inUsers\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string48 = /\/ListRDPConnections\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string49 = /\/LPE_Reflect_Elevate\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string50 = /\/MaceTrap\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string51 = /\/navicatpwd\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string52 = /\/Net\-GPPPassword\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string53 = /\/NoAmci\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string54 = /\/NoPowerShell\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string55 = /\/PrintSpoofer\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string56 = /\/PrintSpoofer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string57 = /\/privilege\sescalation\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string58 = /\/RdpThief\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string59 = /\/RdpThief_x64\.tmp/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string60 = /\/Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string61 = /\/Recon\-AD\-Computers\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string62 = /\/Recon\-AD\-Domain\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string63 = /\/Recon\-AD\-Groups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string64 = /\/Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string65 = /\/Recon\-AD\-SPNs\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string66 = /\/Recon\-AD\-Users\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string67 = /\/ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string68 = /\/RegRdpPort\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string69 = /\/SafetyKatz\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string70 = /\/Seatbelt\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string71 = /\/SessionGopher\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string72 = /\/SessionSearcher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string73 = /\/Sharp3389\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string74 = /\/SharpAVKB\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string75 = /\/SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string76 = /\/SharpChassisType\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string77 = /\/SharpCheckInfo\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string78 = /\/SharpChromium\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string79 = /\/SharpClipHistory\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string80 = /\/SharpCloud\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string81 = /\/SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string82 = /\/SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string83 = /\/SharpDecryptPwd2\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string84 = /\/SharpDir\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string85 = /\/SharpDirLister\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string86 = /\/SharpDomainSpray\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string87 = /\/SharpDoor\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string88 = /\/SharpDoor\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string89 = /\/SharpDPAPI\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string90 = /\/SharpDPAPI\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string91 = /\/SharpDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string92 = /\/SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string93 = /\/SharPersist\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string94 = /\/SharpEventLog\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string95 = /\/SharpExcelibur\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string96 = /\/SharpExec\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string97 = /\/SharpGetTitle\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string98 = /\/SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string99 = /\/SharpHide\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string100 = /\/SharpHound\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string101 = /\/SharpLocker\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string102 = /\/SharpMiniDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string103 = /\/SharpNetCheck\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string104 = /\/SharpOXID\-Find\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string105 = /\/SharpSCshell\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string106 = /\/SharpShares\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string107 = /\/SharpSpray\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string108 = /\/SharpSpray1\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string109 = /\/SharpSQLDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string110 = /\/SharpSQLTools\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string111 = /\/SharpStay\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string112 = /\/SharpTask\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string113 = /\/SharpWeb\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string114 = /\/SharpWebScan\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string115 = /\/SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string116 = /\/sharpwmi\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string117 = /\/SharpXDecrypt\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string118 = /\/SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string119 = /\/Shhmon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string120 = /\/SolarFlare\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string121 = /\/SPNSearcher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string122 = /\/SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string123 = /\/SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string124 = /\/Stealer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string125 = /\/StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string126 = /\/SweetPotato\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string127 = /\/TaoWu\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string128 = /\/Watson\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string129 = /\/WeblogicRCE\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string130 = /\/WMIHACKER\.vbs/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string131 = /\[\!\]\sHoly\shandle\sleak\sBatman\,\swe\shave\sa\sSYSTEM\sshell\!\!/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string132 = /\[\!\]\sSuccess\,\sspawning\sa\ssystem\sshell\!/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string133 = /\\\\windows\\\\temp\\\\123\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string134 = /\\\\Windows\\\\temp\\\\payload\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string135 = /\\add\-admin\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string136 = /\\aggressor\/spoolsystem\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string137 = /\\ATPMiniDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string138 = /\\blocketw\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string139 = /\\blocketw\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string140 = /\\BlockEtw\-master\\/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string141 = /\\BrowserGhost\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string142 = /\\BrowserGhost\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string143 = /\\brute\sforce\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string144 = /\\BypassAddUser\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string145 = /\\BypassAddUser\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string146 = /\\ClearnEventRecordID\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string147 = /\\ClearnIpAddress\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string148 = /\\ClearnTempLog\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string149 = /\\credential\saccess\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string150 = /\\CredPhisher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string151 = /\\CredPhisher\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string152 = /\\cve\-2014\-4113\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string153 = /\\cve\-2014\-4113\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string154 = /\\cve\-2015\-1701\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string155 = /\\cve\-2015\-1701\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string156 = /\\cve\-2016\-0051\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string157 = /\\CVE\-2020\-0796\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string158 = /\\CVE\-2021\-1675\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string159 = /\\dazzleUP_Reflective_DLL\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string160 = /\\DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string161 = /\\DecryptTeamViewer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string162 = /\\DecryptTeamViewer\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string163 = /\\dis_defender\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string164 = /\\Disable\-Windows\-Defender\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string165 = /\\EfsPotato\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string166 = /\\EncryptedZIP\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string167 = /\\FakeLogonScreen\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string168 = /\\FakeLogonScreen\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string169 = /\\frpc\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string170 = /\\fscan\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string171 = /\\FullPowers\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string172 = /\\Gopher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string173 = /\\Gopher\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string174 = /\\hack\-browser\-data\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string175 = /\\InternalMonologue\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string176 = /\\InternalMonologue\.pdb/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string177 = /\\Intranet\spenetration\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string178 = /\\Invoke\-EternalBlue\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string179 = /\\Invoke\-MS16032\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string180 = /\\Invoke\-MS16135\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string181 = /\\JuicyPotato\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string182 = /\\JuicyPotato\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string183 = /\\KillEvenlogService\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string184 = /\\Ladon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string185 = /\\Ladon1\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string186 = /\\Lateral\smovement\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string187 = /\\lazagne\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string188 = /\\ListAllUsers\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string189 = /\\ListLogged\-inUsers\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string190 = /\\ListRDPConnections\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string191 = /\\LPE_Reflect_Elevate\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string192 = /\\MaceTrap\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string193 = /\\navicatpwd\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string194 = /\\Net\-GPPPassword\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string195 = /\\NoAmci\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string196 = /\\NoPowerShell\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string197 = /\\OffensiveCSharp\-master\\/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string198 = /\\PrintSpoofer\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string199 = /\\PrintSpoofer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string200 = /\\privilege\sescalation\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string201 = /\\RdpThief\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string202 = /\\RdpThief_x64\.tmp/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string203 = /\\Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string204 = /\\Recon\-AD\-Computers\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string205 = /\\Recon\-AD\-Domain\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string206 = /\\Recon\-AD\-Groups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string207 = /\\Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string208 = /\\Recon\-AD\-SPNs\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string209 = /\\Recon\-AD\-Users\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string210 = /\\ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string211 = /\\RegRdpPort\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string212 = /\\SafetyKatz\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string213 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string214 = /\\SessionGopher\.ps1/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string215 = /\\SessionSearcher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string216 = /\\Sharp3389\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string217 = /\\SharpAVKB\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string218 = /\\SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string219 = /\\SharpChassisType\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string220 = /\\SharpCheckInfo\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string221 = /\\SharpChromium\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string222 = /\\SharpClipHistory\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string223 = /\\SharpCloud\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string224 = /\\SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string225 = /\\SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string226 = /\\SharpDecryptPwd2\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string227 = /\\SharpDir\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string228 = /\\SharpDirLister\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string229 = /\\SharpDomainSpray\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string230 = /\\SharpDoor\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string231 = /\\SharpDPAPI\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string232 = /\\SharpDPAPI\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string233 = /\\SharpDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string234 = /\\SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string235 = /\\SharPersist\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string236 = /\\SharpEventLog\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string237 = /\\SharpExcelibur\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string238 = /\\SharpExec\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string239 = /\\SharpGetTitle\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string240 = /\\SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string241 = /\\SharpHide\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string242 = /\\SharpHound\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string243 = /\\SharpLocker\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string244 = /\\SharpMiniDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string245 = /\\SharpNetCheck\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string246 = /\\SharpOXID\-Find\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string247 = /\\SharpSCshell\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string248 = /\\SharpShares\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string249 = /\\SharpSpray\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string250 = /\\SharpSpray1\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string251 = /\\SharpSQLDump\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string252 = /\\SharpSQLTools\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string253 = /\\SharpStay\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string254 = /\\SharpTask\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string255 = /\\SharpWeb\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string256 = /\\SharpWebScan\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string257 = /\\SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string258 = /\\sharpwmi\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string259 = /\\SharpXDecrypt\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string260 = /\\SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string261 = /\\Shhmon\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string262 = /\\SolarFlare\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string263 = /\\SPNSearcher\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string264 = /\\SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string265 = /\\SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string266 = /\\Stealer\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string267 = /\\StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string268 = /\\SweetPotato\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string269 = /\\TaoWu\.cna/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string270 = /\\Watson\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string271 = /\\WeblogicRCE\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string272 = /\\windows\\temp\\123\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string273 = /\\Windows\\temp\\payload\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string274 = /\\WMIHACKER\.vbs/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string275 = ">BrowserGhost<" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string276 = ">BypassAddUser<" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string277 = ">DecryptAutoLogon<" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string278 = ">DecryptTeamViewer<" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string279 = ">EfsPotato<" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string280 = "072b5eabc55e8df614786b965d9055fb1414059d28649da7258495f1f5b994d5" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string281 = "07381878641e99bfa6ff286ba7010c04e9055e1dd7c27c079063617a18e1da03" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string282 = "0a1253e1b523145145d03cdbee23afef894beb26fc0c9995588546bbd81d9a3e" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string283 = "0a74fdd3e97e8a940712f5a9cf0052c773b49a39788f3611e73cf00076b608ea" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string284 = "0cb2d09cb81a09c12093fa3cd9739efe998eff21f430375a9b51ee305d8623ac" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string285 = "0cfb136f47821f46d232eb0bd3b37b652d9846c4d66646292a9418c86d1faf47" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string286 = "0d567a5d498809a5595567f9b172fec85c7bd4911da60ce4f2f1729de0bed739" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string287 = "0f3008f8210eb26ea38ca483f561707d720ae97972f63f9d1aa43b42d8beb6b9" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string288 = "0f9529f2e838c7f27f80270aed795440b4545eacb713bfb64e5ba84df104bfa5" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string289 = "12d146f460ca2fca230ba12f1f8ead49340022793ac262b87732a517477c237d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string290 = "18e5187ae45ee5e13379dae0657430a843fae52848b19f572d2fde65906cad4d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string291 = "19a3e58ea39c3de292defd823d99bc5e5a01b6d12e755401178854aaf1c644d5" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string292 = "1a7ef3d45e179cdfc60a891b790f4310c273f0198d330f514ae213a7c4865f67" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string293 = "1b64535871ba5902d04a803aa1e9f746753e42258c104e81a563a4d6bb10ebf7" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string294 = "1da30fe79063333fc5fa8dbf291b5bcc0c07e1ae64722b4de7177eecfa261198" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string295 = "1de72bb4f116e969faff90c1e915e70620b900e3117788119cffc644956a9183" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string296 = "231df570906bdb24f33a92f48448f5ebf4c648fd71c6977956a58adae14aebbc" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string297 = "233d29b4e60407aa550a2e5984ea0fb993f946fa6d83a5505963b4ff4703009f" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string298 = "2623810712c6c081acd999538b5d6a7d28e166bf5e515648d30e30f01ea38e1c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string299 = "2853789802f12b625e35704cd43b0dbcffa250d721721edd9c257c0efa940581" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string300 = "2900497db81e411f0eca52c308b18a7753eb6a7609e702af310773383dc0a1b0" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string301 = "29ca8dc96c56a1198bd34befa9fb5ba1571b24bf1f6f2f4c32eb55fbf47dc6ea" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string302 = "2a059074a33ed243a36891aea3adb60038f81401b3a9f0ec9282350e0450ec3a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string303 = "2aea0b4e3612b01d4550d3014d4324db74406a66e0ab14802b7033564a5771eb" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string304 = "2d3430ea4340df7c6d2e81b8147292f9423871efd5b0da115bd3e9bb7498e014" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string305 = "2ef42f500de7f039f5e2138ccd814afdc7c010e95878d495deb92225aa4e8d4c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string306 = "2ef42f500de7f039f5e2138ccd814afdc7c010e95878d495deb92225aa4e8d4c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string307 = "2f8836f78e6c809950f78fc35d75068f7d5c206947ab009fb7b3c17315f0aded" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string308 = "31108a00a2c2016b0fb4d0e39fb2dbdce141ce9accf9ca0b2cbc47ab2f377cb8" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string309 = "33e7acd14174cdbc8fafe359356c3817df0aa5abded5614c6e2e77ff089e6fb2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string310 = "3467732ca9073986794fb5faef8e37ede70e8fd22dccff7eb484d388ed5b2b14" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string311 = "3a0c9bc22141bf413c8f2719e4266423e3d34b889f357408b4bbec60232bda66" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string312 = "3aad76afcc5d9d5629cb512ca3f8c500fa381231bf15d51b797e30768d5e0e78" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string313 = "3c5ecbc3edd1993243b38576c7b2a1ac16ba7b1ed5194f2cb8daf4a45fd51690" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string314 = "3cdc3d8cd16161b7abedad3d2ed17ce49f03a5ab8b1bf6c09bffd6513f8ba4e0" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string315 = "42f2eae86bb872932ad6081d3b146a59aa2cc109e3a975c3e0a41f41e80599a3" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string316 = "4379af4a67693b483f0b935117a0b377a63a725032da0a25b62dc883a02280b6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string317 = "446a1979c24a8cb2efdd285f14545b1354cd7c06e9d4e69e10a5053158dee119" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string318 = "4527b53e515c275e572f307246614ba4fc9152a25dfd2fd712246b321626bac6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string319 = "459a943f33a20359d1f2dd896ad3ad7c5eb791582c124e851dd2dca6f2088051" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string320 = "469e77c37fbde99cddbaeedd98701e6344665931f382dce3ba36e9e4ea4c3a00" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string321 = "47c9eff8142490a2c341701aab7aaebc355eed1540eed534a8317dd1e65614b2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string322 = "4a642afafcbd3d6f5b704b50ea54ef59b5dea78f679cd7f1513b8d81b8d93cbb" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string323 = "4c4377d6edeb56ea60d2654fec0afc21001cd93ceedaa483f53f66bb61b7904c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string324 = "4c66ef14f4cc5abf79a799b9593298278d636d9150e53b6560351e1ecbd0f6fc" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string325 = "4c9f7dd3c55b538d9c566ca20f097002c54c2b4419066e412ea27cf39fc6a83a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string326 = "4d014c7195a8b7507aa7bc95825371ca83465880e95bdbd411b4dae0a57539af" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string327 = "4d64e31510b95312900f0a12bffb0f9130363da3dcb90cf4e7717427937fe058" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string328 = "4f050eea5800f10338894c847bdbfa5a93bd03115ed7a3c979422f0f0ca95739" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string329 = "4f0fe8424ce7e9de58445e0ca1262d242861bb0239078eae16c41aec863bc09d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string330 = "4f46ef9f5543cd4ca10f4908886e78dccf77b66e5ede7de8e6ec59148309b88b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string331 = "5033ec3ed6f2c060b95608439b3d3f69295b6b9a344e638e1412a208fa2357b2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string332 = "55155cb2d44c4f860926098d53a96904a1ac89e04130d8db431a2170b389696b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string333 = "56937d0eb5b5702acd0a7d19206c3e79b99e5e334544a47b342fb4a845f8f29b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string334 = "58359209e215a9fc0dafd14039121398559790dba9aa2398c457348ee1cb8a4d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string335 = "58de3ab6935d1248e937e333e917586efb058e8b7d65ade38989543c806bd23e" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string336 = "591c23bad87621b0cf6f2e5f27f038205e11a9241f83ab28bbafed575d8fd6b6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string337 = "5a21e58cf302bd2ff1cd95bceaaae6f22151ac15af52ea1249b2e0ddfffe704f" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string338 = "5ba530ebd87d7cb1bc0a2a368bdab568bf533a4da5399428feadc79a7947eb9d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string339 = "60c1ea95d10c8223eae771a2261117a4cbd7265b76e5dcf5bc0583f2a095de11" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string340 = "6142cafb3387eb72f07e6f420aa519affd5fcba4a48459d5084678bc9e661e44" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string341 = "66b63cd9f55f90b78592f0b6d9fd5ba8b8b31b538bd20be459f2a380811f4d13" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string342 = "67f8634f21a97d71f8baba63156aa6a50918fbd9df054c23b28138ceaa39ba34" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string343 = "690a75c3c6d282677102073f6bc64c4f8a13771aa052497ba02ca19a6de56f8a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string344 = "6b9c155d3ce702c042f0ce00d42909fd7fb0a3f37e2f477dbdb40b0881d4e2d5" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string345 = "6c174114cc8159ea4a8614b5418fa6e6405c42c64675657f69b1ae1839dd0a70" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string346 = "6d878963a9bc68106e1a6bfdbde3e2d72445d86e65c1613cd07344104c0995c2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string347 = "6e5cbf14240bc5d146d5516257163145cba176066d6c43d55d757101c2517587" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string348 = "6fad3a96fe407982818ce27f73c78b8ac3b0902bd85f104dc85eef092f4186de" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string349 = "70f0161252fd75f2cbd71a5fadaa3346b5336bdfebfcf27fa70f37349d193513" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string350 = "71a4456ea5aa14b3799672c2b57a2629a2ed5e0f3183a06bf9e3464d99b3941a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string351 = "71db9ab725d24be869c01d97f1557548766eb06d0bd2891557d6388628f9ada6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string352 = "73b0c526db81c60a58abf4a5b7e6f6eb7959efb0b5b65c16afa105d74342a9ae" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string353 = "76a3395be39125fa1185032ca854ebd68bcb2229fa6802d9012bddcbe3b1f2ac" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string354 = "795bdabf997860026137d283b1536fb91ec13dba6eeea0b3d034a030e801efe7" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string355 = "796f70f7e01257c5b79e398851c836e915f6518e1e3ecd07bcd29233cf78f13d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string356 = "7a8911925aadc8e4140a62e5467e01072148a5bb6c408fb083de934d3eb9bde0" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string357 = "7afd2ebbf1c75880581e485fdd64d4b4cbb658a79cf271c0afa8092b8ce937ce" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string358 = "7d6c67ce067fc1f459e617e2cb6d891e74ccdf3b4630fd64cb824b230a74dc8c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string359 = "8034c131c03f032538aac5c7619732804c64e7e619e4dc27614ecedfdbe2afd5" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string360 = "811b4a92ff8cf7ae50e4edaa23c2d533662a8ce035ba079792bfe21e0457b19b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string361 = "8177096d8c171e68e1ad0cfae755ad4e7fafa97ef18f5400db34ec157616623a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string362 = "8245a0542c25505872414878bbb0bac624145b348d83e458a079732c9c457924" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string363 = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string364 = "83e20b2fc8347cb5765a8c622ce59806a900f735088c3c9a385676f4e01849ce" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string365 = "8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string366 = "886ce8cf3c9c8a6e8a4db1c3286151c9af6a3fbe7269a5df5269d9ffa6a8c992" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string367 = "8905becea35b76ddcebac536548ccf08a14eb684fac25063a350c9d0b3a95369" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string368 = "89379d7dcc96b1f8399884532c399c7522bdde6aed85b483e1ff81c6deab4f7b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string369 = "89fa21c871572c227274d7836c88e815b748db63f6a662553a43cc1dd086667c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string370 = "8b3f9a3242e75005203ff26e3a5af76bb57ebce8fb29c13559b3bccfa7c4cce3" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string371 = "8cb248d6558fad8e94bc615b3db1ec567c6d9cd30d48f4dc58af4449d626abf7" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string372 = "8f32c6af660897e07089798972eaba79006a5aeeb7a96327a597d4e47eaa34d9" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string373 = "902d0c9bf021c0320c144524268e05f889f733e07b76c24ebdda299e0508239a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string374 = "9092e23d27fe808acb7485c1cabd30ce0eb89cbdce51da83725668b4305ad2eb" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string375 = "916e582e5bcc71068ce6e2051a05772affd07e53f41518e61808b6c0777a1d3f" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string376 = "96453b2663149a1019d5585d8a3e67961db6c6c8d43cb76756b14195a839d35e" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string377 = "97e6a954a2bb21afcc7eeab6ec6d95c6c174ebb7b5fd1da881ab51f74dc944c7" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string378 = "997cd811395cfa507c03ba12937f1b8b767f03c146de3771f3fdf66ed2f821c1" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string379 = "9994297041105099a5d6870a6d0f1ac5f53035758b053349a76007a3d74ff93d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string380 = "9a85168c858654fac9052dc60b13a8c4e43c3621ea73ff3e4e9e3a6159662cfc" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string381 = "9c0a560217bcbdd543c9f90eff81b714f4ddcbea9be1bd69c4c348f251be9b88" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string382 = "9c48888489f9c1b82e0b6db9725e9adb9cad702c8ba2de6dce77b2f560df855b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string383 = "9fa36e9dbce91b0a9e691b8664ecce4953eebf7ce6260f71f5b9accc46694d70" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string384 = "9fd62a2ee41355f974bf08ef13a49c7007c39f0f088e4f4fefb526ded4de44d9" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string385 = "a04da1ed67edcc4e11d49aeac5aeac4cb09dcdda5e2347a1ce77fa4a079482f1" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string386 = "a0bc5a42f2415d9efc221c2ffa9d2ef131351be75d4494f84fefff7bf5427323" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string387 = "a36223683b1c817d0682ecbee3f3c2d8c60259253dc70969110aed4a3bb4ccfa" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string388 = "a38f6ecc6230b87a0da055351528416f5150c6ec5e1b505043883a142cd36f14" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string389 = "a43bb6f7722fc5426cf74039935d60d648f085aa1f463ec94c32add776fa3928" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string390 = "a97c94ee538d84474a794fdcf7e2f17735aeb7b62be66e1775ad396a4c5357a2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string391 = "aa96d396459aa3f3456ec948d37d92cb605fee98c72a5b64215c259113660518" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string392 = "ab18ba41a3ac4e39a62403d4c926969bf73df5e364c290c87508c006df13e9a8" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string393 = "ac4329a75f33a71b5b4ece7aeae9d6e09e99b033809b85b7f1ebb2e80f32ab3a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string394 = "acc9c65557132735ab0c7aae5bb2e2f996ab24508b37e62a8bb1024f3e1f1b14" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string395 = "ad1fdf36f0f9507ddfe59e2dcab4ee246be5c9ddfb674107bf313c21655d4b0c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string396 = "ad577ef615bc0658fcb17bbb64afc2b7a3f487cd1eb7c2b673357d1df622fa78" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string397 = "ad76055ffa760f3aac8cf5dca9e2380246abb919484b28ed8d5c2ca1a6066e31" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string398 = "af8f26e8a970e480790b6c09289d3ab4a2dbf6097b3ac5dac323ac9ea433531a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string399 = /artofpwn\.com/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string400 = "b5d90d409125ed0f45be4d92aef25f2ed8faca96d076d28051645c72b5ad45c9" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string401 = "b9af7e45ec82950abedd3e86d466d275f0e19856c0a0fe52fc9c2349d77aa7c2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string402 = "bb91387aea9bb46572a1b0a0be195f8ca26f47c7e5dc42c04b5b8a614a686c31" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string403 = "bdd8493bc9a1be6b5018c949bd3fc60831b83e0c97ff31933a0e9516a25947a2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string404 = "bf7120a63483a2e4300a4d1405ac7525f11dd1f6d6a7120767bc42566da35891" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string405 = /bpowershell_import\(/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string406 = "c2494e6e5e6496d3d04fb69927a25c8cead06e68cd2d4005ee4b3853770ece4f" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string407 = "c3b6f81b25c7315d9a856dbc0ed1b129b2e0b39553fbd8a50a4145de6aa8ed42" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string408 = "c5fcec5642fc333a1dda82ebde876d7bbe38d63a6eb54fc80bf7b9cf00fd8ae0" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string409 = "c676b559a0d13fec22804c9489726a9a6ffbb6260c866cb5e5964067ea733bcc" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string410 = "c685c2c3c886ac36781acaafd1292c4d25d4721299dcdaa1c0a79dac5ec469da" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string411 = "c74897b1e986e2876873abb3b5069bf1b103667f7f0e6b4581fbda3fd647a74a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string412 = "c78a157fbea4f59374fa0b274ab267549a664023443da600524146a13eb8b214" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string413 = "c7ff56000d015b06e6767e9bd7f2164e3876011d98ccd242c9d98dc11036d96a" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string414 = "ca2034f590d15577047e447e717299856b1a4518fd2fe6eef04429c344e0f206" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string415 = "ca56cf7dc2c29e1556f3fe3476ed76b18ab96372ca941bc92e22873c3472bd81" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string416 = "caf10b7ae65ee32d8a5fc68bfe5fa8bbe73a3ebd5a9602ebf49ec977edb1e38b" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string417 = "cd7e4cd71cb803de24f7b8fc6c6946f96e9b9a95dd3c0888309b42446ba87b94" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string418 = "cd8a7916f5beb7a221186784fe7b0b2c4cd01104d699e78bef786b0f9ccf6640" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string419 = "ce0ae1416a4841144e8a377eed2a11fef988b08042606bac8121b4a4abd5391e" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string420 = "cfe69a909f43c5734f180e5d0583d8f56d8f7a6cf87c36d43625d3bfa786e7ca" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string421 = /ClearnEventRecordID\s\{/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string422 = /cmd\.exe\s\/c\snetsh\sadvfirewall\sfirewall\sadd\srule\sname\=.{0,1000}\sprotocol\=TCP\sdir\=in\slocalport\=3389\saction\=allow/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string423 = "d68790ec9278e5bcaddc365ff394278cd02e55b0a1526a5f9e7df9dcbc7d25db" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string424 = "d7a308da069dcf3990f4cbfe57b8a1cc79c5f6b1259da795bba61592b8cf4b08" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string425 = "dabac1fe57c2338d9eb6360fbb4627cdfbec3edd37bab8926333c0610b2499b7" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string426 = "ddbf3299675ffdd7e3475f8a4848f3ab6cdff8819348c75b9ac4d8fb76569a2c" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string427 = "ddd36cf834fc7dca78f2d96e954e0949043c1c63aa268cfc18774e9875e63192" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string428 = "DecryptNextCharacterWinSCP" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string429 = "DecryptWinSCPPassword" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string430 = /del\s\/f\s\/s\s\/q\sfscan\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string431 = /del\s\/f\s\/s\s\/q\snpc\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string432 = "DownloadAndExtractFromRemoteRegistry" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string433 = "e00489f1e9416d9d857d35b22e5e9ad23b6afdadc0da7bc3687df67c49e870c0" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string434 = "e01dc0dc7863c3603c388e7a0629420dea1d437cefe6f385829054589d58e913" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string435 = "e1d9d19cb999647e1261d85578063cb1bd62a0f62ee22dadfdfa0ffd7f567fd6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string436 = "e1eeb3735ada6088c8b1a740671d4430b26249f1f9b09b5052a00d398c832815" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string437 = "e5677fba46f78b856db90d573786aa5a46f068ddc9d5565ebb16a16795d05693" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string438 = "e6dff41219521c5b2daf06379ac793df0a633b7271c8fd7c482c950eb655c182" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string439 = "e6f2b9e53c7e38b725dd5605fb1d6527128bfe0f9a17ef305505bdc7a0771a79" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string440 = "e79c8cadd9b100cb8c9efcc4c67bf33049a4423c08c083913f03e53024e7b3d6" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string441 = "e8950dfc957d2323f55944075134ff945bb8c467e48c1b4b7c86725b09460da2" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string442 = "e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string443 = "ea3749e4487dc724a97d4794a19b2921814b57087aafc66176c434c9605fe939" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string444 = "ea8adcdf44d1dfe4f0e44d265967e1beb1ac6eaf7c0fae943a4baaf0b7d1bbdb" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string445 = "ec75e03dbec89909be98b833209c2a422ba68f24b0e45818d55b29174d5588b9" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string446 = "f49651f69f442cc4e54941b1bbfa53c3bf2680e889963dc1e2b3e8cb82695b09" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string447 = "f630a53430993faf0efc789c5e00680c3c2e83883e44a93565752a4f490dd41d" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string448 = "f75750934e4291853a7f536ba36a8e478066105b7c2b8d256d4ecb17d8bc60ee" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string449 = "f77bd4b1b89324c9b873cd5552249c0217d1fd82a317b88e9c78a59448192f87" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string450 = "f9da84d51a436405bfde86e2a5abbb4bd19cc1226bc07a9f89c1153437a70797" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string451 = "faab30099ca682a0b9f183c1e0319a6e16656e09bdcbfa410a590e07694c2850" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string452 = "Invoke-EternalBlue" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string453 = /iox\.exe\sfwd\s\-r\s/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string454 = /KillEvenlogService\s\{/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string455 = /powerpick\scertutil\.exe\s\-urlcache\s\-split\s\-f\s/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string456 = "sharpDPAPI_masterkeysToClipboard" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string457 = /taskkill\s\-f\s\/im\schfs\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string458 = /taskkill\s\-f\s\/im\scrack\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string459 = /taskkill\s\-f\s\/im\sfrpc\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string460 = /taskkill\s\-f\s\/im\siox\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string461 = /taskkill\s\-f\s\/im\slazagne\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string462 = /taskkill\s\-f\s\/im\smodify\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string463 = /taskkill\s\-f\s\/im\snpc\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string464 = /taskkill\s\-f\s\/im\sscrying\.exe/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string465 = /WMIHACKER\.vbs/ nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string466 = "Xiangshan@360RedTeam" nocase ascii wide
        // Description: Collection of hacktools binaries
        // Reference: https://github.com/pandasec888/taowu-cobalt_strike/tree/312fec79b3413ecfc06bc43efccfcbc1383a3566
        $string467 = "pandasec888/taowu-cobalt_strike" nocase ascii wide

    condition:
        any of them
}
