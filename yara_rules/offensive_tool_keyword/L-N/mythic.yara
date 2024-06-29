rule mythic
{
    meta:
        description = "Detection patterns for the tool 'mythic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mythic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string1 = /\sAthena\.Commands/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string2 = /\sAthena\.Models\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string3 = /\sathena\.mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string4 = /\sc2\sadd\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string5 = /\sc2\sstart\shttp\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string6 = /\sDInvokeResolver\./ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string7 = /\sinstall\sgithub\s.{0,1000}merlin/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string8 = /\smerlin\.py\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string9 = /\smythic\sstart/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string10 = /\smythic_container\.Mythic/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string11 = /\smythic_payloadtype_container/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string12 = /\smythic\-cli/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string13 = /\spayload\sadd\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string14 = /\spayload\sstart\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string15 = /\stdotnet\spublish\sAthena\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string16 = /\.athena_utils\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string17 = /\.get_c2profile/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string18 = /\/adcs\-enum\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string19 = /\/agent_code\/Apollo\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string20 = /\/agent_code\/Athena/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string21 = /\/agent_code\/cmd_executor/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string22 = /\/agent_code\/dll\.go/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string23 = /\/agent_code\/merlin\./ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string24 = /\/agent_code\/powershell_executor/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string25 = /\/agent_code\/sh_executor/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string26 = /\/agent_code\/zsh_executor/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string27 = /\/agent_functions\/.{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string28 = /\/agent_icons\/athena\.svg/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string29 = /\/agents\/thanatos\/commands\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string30 = /\/amsi\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string31 = /\/Apollo\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string32 = /\/Apollo\.git/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string33 = /\/Apollo\/Agent\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string34 = /\/ApolloInterop\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string35 = /\/ApolloInterop\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string36 = /\/ApolloTest\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string37 = /\/Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string38 = /\/Athena\.csproj/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string39 = /\/Athena\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string40 = /\/Athena\.Profiles\..{0,1000}\.cs/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string41 = /\/Athena\.Profiles\..{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string42 = /\/Athena\.Profiles\..{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string43 = /\/Athena\.sln/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string44 = /\/Athena\/Assembly\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string45 = /\/Athena\/Commands\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string46 = /\/athena\/mythic/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string47 = /\/athena_utils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string48 = /\/AthenaPlugins\/bin\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string49 = /\/AthenaSMB\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string50 = /\/AthenaTests\/.{0,1000}\./ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string51 = /\/bash_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string52 = /\/c2_code\/.{0,1000}\.html/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string53 = /\/c2_code\/server/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string54 = /\/C2_Profiles\// nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string55 = /\/cmd_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string56 = /\/DInvoke\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string57 = /\/DInvokeResolver\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string58 = /\/documentation\-c2\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string59 = /\/documentation\-payload\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string60 = /\/enable\-user\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string61 = /\/Example_C2_Profile/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string62 = /\/Example_Payload_Type\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string63 = /\/fake\.html/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string64 = /\/freyja\.go/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string65 = /\/freyja_tcp\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string66 = /\/get\-clipboard\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string67 = /\/inline\-exec\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string68 = /\/kerberoast\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string69 = /\/kerberoast\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string70 = /\/kerberoast\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string71 = /\/keylogger\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string72 = /\/load\-assembly\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string73 = /\/Management\/C2\// nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string74 = /\/merlin\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string75 = /\/merlin\/agent_code\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string76 = /\/Mythic\/mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string77 = /\/Mythic_CLI/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string78 = /\/MythicAgents\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string79 = /\/MythicAgents\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string80 = /\/MythicC2Profiles\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string81 = /\/mythic\-cli/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string82 = /\/MythicConfig\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string83 = /\/mythic\-react\-docker/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string84 = /\/nanorubeus\// nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string85 = /\/opt\/merlin\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string86 = /\/outflank_bofs\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string87 = /\/payload_service\.sh/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string88 = /\/Payload_Type\/athena/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string89 = /\/Payload_Types\// nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string90 = /\/powershell_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string91 = /\/schtasksenum\/.{0,1000}\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string92 = /\/ScreenshotInject/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string93 = /\/sh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string94 = /\/SMBForwarder\.txt/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string95 = /\/thanatos\.dll/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string96 = /\/thanatos\.exe/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string97 = /\/thanatos\.git/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string98 = /\/thanatos\/releases\// nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string99 = /\/thanatos\/releases\/latest/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string100 = /\/thanatos\/thanatos\/agent_code\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string101 = /\/timestomp\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string102 = /\/trusted_sec_bofs\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string103 = /\/trusted_sec_remote_bofs\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string104 = /\/UACBypasses\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string105 = /\/vss\-enum\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string106 = /\/win\-enum\-resources/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string107 = /\/zsh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string108 = /\\Apollo\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string109 = /\\Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string110 = /\\thanatos\.dll/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string111 = /\\thanatos\.exe/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string112 = /04211dce315cd4a178578452d67ed6cb281073f05d70ad51b758131171b1a072/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string113 = /062c58fd40ba2db0ca413999598afee2beabf79f16ca0308c0565e19614d8487/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string114 = /10d06380c1904999c36072f962cfe380fe36488c3bcf1a2f485532de4d5bae5f/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string115 = /12aa6879942823c8807fa8fb30e248e1c0504c2588995ff6930c446eb2b999d5/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string116 = /16d582a5722d39a87d530e62c732864b8eeb9b039ca9b769888e53539b21371e/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string117 = /1eca6224c1b88fb220bbfa728cf27f260fb1ea27d5520167fd98ca25b0e5c1c8/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string118 = /20749471886fbeb543555c1060694f64891eb0a41adae19f747b2c635b2a3a94/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string119 = /27f443acc6d3ba9588017121dc2e70f8aed6224a69d8f41b0a51afb21b8fd259/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string120 = /331494b772e936769247a43746a6ac828257c145cb3e514e8682ceb5d58af06f/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string121 = /3c625eb5dbccce53faab97b9bfd0ef14f6c08730eae0d6442d201a64597c96ea/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string122 = /5059f0c09b5561445b48a8566a3754caf1472f8539194b35428bb3ff7690f06e/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string123 = /590cdf2dfb21bf5ee5fcdfe1f37bd530cbd946cfcc43f8e644638486b06cdc18/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string124 = /7443\/new\/payloads/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string125 = /7d621fe424daf7ca2a90cc1167ae8a9fc8eca96c82821acf6a2fa3fe7683603c/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string126 = /894399f27a67fa61608ef9a098bf9dc3ec009582d98193616cde9ab3b59f7a51/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string127 = /ab945e611084c9deccab6780df91caadf44977d54e61f621d2a5686a217a0a73/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string128 = /ae136c5aa1e9a4524f30350fc8fc45993e2a81d0ffab2d7c4bd0f9ae7cea2060/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string129 = /agent_code\/bash_executor/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string130 = /Athena\.Forwarders\.SMB/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string131 = /athena\/agent_code\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string132 = /AthenaPlugins\.csproj/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string133 = /bash_executor\s/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string134 = /bdf481e2b241169231c72a3f811c69f97526db060e11c2e7e7c1e39dadf4ac89/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string135 = /blockdlls\s\-/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string136 = /build\.ps1\s\-commands\s.{0,1000}\s\-profile\s.{0,1000}selfcontained\s\-singlefile/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string137 = /build\.ps1\s\-profiles\s.{0,1000}\s\-commands\s.{0,1000}\s\-compressed/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string138 = /C2_RPC_functions\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string139 = /c2_service\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string140 = /C2ProfileManager\./ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string141 = /cdd738401073d7c2c6b919b1a97e136c12467c6ccfbdc1f8b55baa67e4f9afe7/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string142 = /\-cli\sinstall\sgithub\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string143 = /\-cli\sinstall\sgithub\s.{0,1000}Apollo\./ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string144 = /\-cli\spayload\sstart\s/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string145 = /cmd_executor\s/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string146 = /d65a63d32b46e3b20f42174834f5a367ab0ffbfc1b0bd4b368613c86d01a71e2/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string147 = /dcsync\s\-Domain/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string148 = /docs\.mythic\-c2\.net/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string149 = /e542e94c43340357ded227e309c20e1e03505295a8dba216781f2976ff29c449/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string150 = /execute_pe\s\-PE/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string151 = /execute\-assembly\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string152 = /execute\-pe\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string153 = /execute\-shellcode\.py/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string154 = /f9c1f7d62460e7ab424bacb00361ec645816cf478c9308ede41ac926c5012db3/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string155 = /fb8b5d212f449a8ba61ab9ed9b44853315c33d12a07f8ce4642892750e251530/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string156 = /from\smerlin\simport\s/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string157 = /from\smythic_container\.MythicCommandBase/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string158 = /from\smythic_container\.MythicGoRPC/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string159 = /get_injection_techniques/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string160 = /GETCLIPBOARD.{0,1000}GETLOCALGROUP/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string161 = /get\-password\-policy\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string162 = /github\.com\/MythicAgents\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string163 = /golden_ticket\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string164 = /http\:\/\/127\.0\.0\.1\:7444/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string165 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string166 = /import\smythic/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string167 = /inline_assembly\s\-Assembly\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string168 = /inline\-exec\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string169 = /issue_shell_whoami/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string170 = /its\-a\-feature\/Apfell/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string171 = /its\-a\-feature\/Mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string172 = /its\-a\-feature\/Mythic/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string173 = /keylog_inject\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string174 = /keylog_inject\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string175 = /killprocess\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string176 = /link_tcp\s127\.0\.0\.1\s/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string177 = /merlin\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string178 = /mimikatz\s\-Command\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string179 = /MockDirUACBypassDll/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string180 = /mythic_c2_container/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string181 = /mythic_nginx/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string182 = /mythic_payloadtype/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string183 = /mythic_payloadtype/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string184 = /mythic_payloadtype_container/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string185 = /mythic_rest\.Payload/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string186 = /mythic_service\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string187 = /mythic_translator_containter/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string188 = /MythicAgents\/Apollo/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string189 = /MythicAgents\/Athena/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string190 = /MythicAgents\/merlin/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string191 = /MythicAgents\/thanatos/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string192 = /mythic\-cli\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string193 = /mythic\-cli.{0,1000}athena/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string194 = /MythicClient\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string195 = /mythic\-docker/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string196 = /nanorobeus\.x64\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string197 = /nanorubeus\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string198 = /net_dclist\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string199 = /net_localgroup_member\s\-Group/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string200 = /Payload_Type\/freyja\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string201 = /\-PID\s.{0,1000}\s\-Assembly\s.{0,1000}\s\-Arguments\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string202 = /powerpick\s\-Command\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string203 = /printspoofer\s\-Command/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string204 = /printspoofer\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string205 = /PrintSpoofer_x64\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string206 = /psinject\s\-PID/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string207 = /run\s\-Executable\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string208 = /screenshot_inject\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string209 = /set_injection_technique/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string210 = /setup_apfell\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string211 = /spawnto_x64\s\-Application\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string212 = /spawnto_x64\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string213 = /spawnto_x86\s\-Application/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string214 = /spawnto_x86\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string215 = /start_mythic_server\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string216 = /steal_token\s/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string217 = /steal_token\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string218 = /TicketToHashcat\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string219 = /zsh_executor\s/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string220 = /sh_executor\s/ nocase ascii wide

    condition:
        any of them
}
