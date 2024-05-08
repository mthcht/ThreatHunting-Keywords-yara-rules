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
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string29 = /\/amsi\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string30 = /\/Apollo\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string31 = /\/Apollo\.git/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string32 = /\/Apollo\/Agent\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string33 = /\/ApolloInterop\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string34 = /\/ApolloInterop\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string35 = /\/ApolloTest\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string36 = /\/Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string37 = /\/Athena\.csproj/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string38 = /\/Athena\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string39 = /\/Athena\.Profiles\..{0,1000}\.cs/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string40 = /\/Athena\.Profiles\..{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string41 = /\/Athena\.Profiles\..{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string42 = /\/Athena\.sln/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string43 = /\/Athena\/Assembly\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string44 = /\/Athena\/Commands\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string45 = /\/athena\/mythic/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string46 = /\/athena_utils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string47 = /\/AthenaPlugins\/bin\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string48 = /\/AthenaSMB\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string49 = /\/AthenaTests\/.{0,1000}\./ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string50 = /\/bash_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string51 = /\/c2_code\/.{0,1000}\.html/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string52 = /\/c2_code\/server/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string53 = /\/C2_Profiles\// nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string54 = /\/cmd_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string55 = /\/DInvoke\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string56 = /\/DInvokeResolver\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string57 = /\/documentation\-c2\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string58 = /\/documentation\-payload\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string59 = /\/enable\-user\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string60 = /\/Example_C2_Profile/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string61 = /\/Example_Payload_Type\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string62 = /\/fake\.html/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string63 = /\/freyja\.go/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string64 = /\/freyja_tcp\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string65 = /\/get\-clipboard\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string66 = /\/inline\-exec\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string67 = /\/kerberoast\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string68 = /\/kerberoast\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string69 = /\/kerberoast\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string70 = /\/keylogger\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string71 = /\/load\-assembly\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string72 = /\/Management\/C2\// nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string73 = /\/merlin\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string74 = /\/merlin\/agent_code\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string75 = /\/Mythic\/mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string76 = /\/Mythic_CLI/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string77 = /\/MythicAgents\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string78 = /\/MythicAgents\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string79 = /\/MythicC2Profiles\// nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string80 = /\/mythic\-cli/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string81 = /\/MythicConfig\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string82 = /\/mythic\-react\-docker/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string83 = /\/nanorubeus\// nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string84 = /\/opt\/merlin\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string85 = /\/outflank_bofs\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string86 = /\/payload_service\.sh/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string87 = /\/Payload_Type\/athena/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string88 = /\/Payload_Types\// nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string89 = /\/powershell_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string90 = /\/schtasksenum\/.{0,1000}\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string91 = /\/ScreenshotInject/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string92 = /\/sh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string93 = /\/SMBForwarder\.txt/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string94 = /\/timestomp\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string95 = /\/trusted_sec_bofs\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string96 = /\/trusted_sec_remote_bofs\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string97 = /\/UACBypasses\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string98 = /\/vss\-enum\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string99 = /\/win\-enum\-resources/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string100 = /\/zsh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string101 = /\\Apollo\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string102 = /\\Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string103 = /7443\/new\/payloads/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string104 = /agent_code\/bash_executor/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string105 = /Athena\.Forwarders\.SMB/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string106 = /athena\/agent_code\// nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string107 = /AthenaPlugins\.csproj/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string108 = /bash_executor\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string109 = /blockdlls\s\-/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string110 = /build\.ps1\s\-commands\s.{0,1000}\s\-profile\s.{0,1000}selfcontained\s\-singlefile/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string111 = /build\.ps1\s\-profiles\s.{0,1000}\s\-commands\s.{0,1000}\s\-compressed/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string112 = /C2_RPC_functions\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string113 = /c2_service\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string114 = /C2ProfileManager\./ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string115 = /\-cli\sinstall\sgithub\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string116 = /\-cli\sinstall\sgithub\s.{0,1000}Apollo\./ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string117 = /\-cli\spayload\sstart\s/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string118 = /cmd_executor\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string119 = /dcsync\s\-Domain/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string120 = /execute_pe\s\-PE/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string121 = /execute\-assembly\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string122 = /execute\-pe\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string123 = /execute\-shellcode\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string124 = /fb8b5d212f449a8ba61ab9ed9b44853315c33d12a07f8ce4642892750e251530/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string125 = /from\smerlin\simport\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string126 = /get_injection_techniques/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string127 = /GETCLIPBOARD.{0,1000}GETLOCALGROUP/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string128 = /get\-password\-policy\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string129 = /github\.com\/MythicAgents\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string130 = /golden_ticket\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string131 = /http\:\/\/127\.0\.0\.1\:7444/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string132 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string133 = /import\smythic/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string134 = /inline_assembly\s\-Assembly\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string135 = /inline\-exec\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string136 = /issue_shell_whoami/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string137 = /its\-a\-feature\/Apfell/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string138 = /its\-a\-feature\/Mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string139 = /its\-a\-feature\/Mythic/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string140 = /keylog_inject\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string141 = /keylog_inject\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string142 = /killprocess\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string143 = /link_tcp\s127\.0\.0\.1\s/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string144 = /merlin\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string145 = /mimikatz\s\-Command\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string146 = /MockDirUACBypassDll/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string147 = /mythic_c2_container/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string148 = /mythic_nginx/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string149 = /mythic_payloadtype/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string150 = /mythic_payloadtype/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string151 = /mythic_payloadtype_container/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string152 = /mythic_rest\.Payload/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string153 = /mythic_service\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string154 = /mythic_translator_containter/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string155 = /MythicAgents\/Apollo/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string156 = /MythicAgents\/Athena/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string157 = /MythicAgents\/merlin/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string158 = /mythic\-cli\s/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string159 = /mythic\-cli.{0,1000}athena/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string160 = /MythicClient\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string161 = /mythic\-docker/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string162 = /nanorobeus\.x64\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string163 = /nanorubeus\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string164 = /net_dclist\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string165 = /net_localgroup_member\s\-Group/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string166 = /Payload_Type\/freyja\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string167 = /\-PID\s.{0,1000}\s\-Assembly\s.{0,1000}\s\-Arguments\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string168 = /powerpick\s\-Command\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string169 = /printspoofer\s\-Command/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string170 = /printspoofer\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string171 = /PrintSpoofer_x64\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string172 = /psinject\s\-PID/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string173 = /run\s\-Executable\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string174 = /screenshot_inject\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string175 = /set_injection_technique/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string176 = /setup_apfell\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string177 = /spawnto_x64\s\-Application\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string178 = /spawnto_x64\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string179 = /spawnto_x86\s\-Application/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string180 = /spawnto_x86\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string181 = /start_mythic_server\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string182 = /steal_token\s/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string183 = /steal_token\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string184 = /TicketToHashcat\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string185 = /zsh_executor\s/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string186 = /sh_executor\s/ nocase ascii wide

    condition:
        any of them
}
