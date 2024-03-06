rule nemesis
{
    meta:
        description = "Detection patterns for the tool 'nemesis' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nemesis"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string1 = /\s11_Credentials\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string2 = /\s13_NoseyParker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string3 = /\s17_Custom_Cracklist\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string4 = /\s9_DPAPI\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string5 = /\sbof_reg_collect_parser\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string6 = /\schromium_history\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string7 = /\schromium_logins\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string8 = /\scrack_list\sclient_wordlists\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string9 = /\scrack_list\scracklist_api\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string10 = /\scrack_list\sdictionary\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string11 = /\scrack_list\swordlist\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string12 = /\sdpapi_domain_backupkey\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string13 = /\sdpapi_masterkey\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string14 = /\sDPAPImk2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string15 = /\sjohn_the_ripper_cracker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string16 = /\s\-m\senrichment\.cli\.submit_to_nemesis/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string17 = /\snemesis_connector\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string18 = /\snemesis_db\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string19 = /\snemesis_reg_collect_parser\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string20 = /\snemesis\-cli\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string21 = /\soffice2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string22 = /\spasswd\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string23 = /\spassword_cracker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string24 = /\spdf2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string25 = /\sreg_hive_sam\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string26 = /\sreg_hive_security\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string27 = /\sreg_hive_system\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string28 = /\sseatbelt_json\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string29 = /\ssecretsdump\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string30 = /\ssliver_pb2\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string31 = /\ssliver_pb2_grpc\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string32 = /\ssubmit_to_nemesis\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string33 = /\ssubmit_to_nemesis\.sh/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string34 = /\s\-\-user\s\'nemesis\:/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string35 = /\.\/agscript\s.{0,1000}\snemesis\-bot\s/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string36 = /\/11_Credentials\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string37 = /\/13_NoseyParker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string38 = /\/17_Custom_Cracklist\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string39 = /\/9_DPAPI\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string40 = /\/bof_reg_collect_parser\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string41 = /\/chromium_history\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string42 = /\/chromium_logins\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string43 = /\/cobaltstrike\-nemesis\-connector\// nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string44 = /\/crack_list\/client_wordlists\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string45 = /\/crack_list\/cracklist_api\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string46 = /\/crack_list\/dictionary\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string47 = /\/crack_list\/wordlist\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string48 = /\/custom_crack_list\.txt/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string49 = /\/dpapi_domain_backupkey\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string50 = /\/dpapi_masterkey\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string51 = /\/DPAPImk2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string52 = /\/john_the_ripper_cracker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string53 = /\/Nemesis\.git/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string54 = /\/nemesis_connector\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string55 = /\/nemesis_db\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string56 = /\/nemesis_reg_collect_parser\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string57 = /\/nemesis\-cli\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string58 = /\/office2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string59 = /\/opt\/cobaltstrike\-nemesis/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string60 = /\/passwd\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string61 = /\/password_cracker\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string62 = /\/passwordcracker\.Dockerfile/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string63 = /\/passwordcracker\// nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string64 = /\/pdf2john\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string65 = /\/reg_hive_sam\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string66 = /\/reg_hive_security\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string67 = /\/reg_hive_system\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string68 = /\/seatbelt_json\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string69 = /\/secretsdump\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string70 = /\/sliver_pb2\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string71 = /\/sliver_pb2_grpc\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string72 = /\/submit_to_nemesis\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string73 = /\/submit_to_nemesis\.sh/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string74 = /\/submit_to_nemesis\.yaml/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string75 = /\/wordlists\/top_10000\.txt/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string76 = /\/wordlists\/top_100000\.txt/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string77 = /\:8080\/yara\/file/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string78 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string79 = /AWS_BUCKET\=nemesis\-test/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string80 = /AWS_KMS_KEY_ALIAS\=nemesis\-dev/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string81 = /class\sPlugin\:\:Nemesis\s\<\sMsf\:\:Plugin/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string82 = /cobaltstrike\-nemesis\-connector/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string83 = /create_nemesis_db\(/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string84 = /create_nemesis_db_pool\(/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string85 = /def\snemesis_post_data\(/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string86 = /export\sNEMESIS_BASE_URL/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string87 = /export\sNEMESIS_CREDS/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string88 = /file_parsers\/group_policy_preferences\.py/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string89 = /getLogger\(\"NemesisConnector\"\)/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string90 = /http\:\/\/nemesis\/file/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string91 = /http\:\/\/nemesis\/yara/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string92 = /http\:\/\/nemesis\-es\-http\.default\.svc\.cluster\.local\:9200/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string93 = /http\:\/\/nemesis\-es\-internal\-http\:9200/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string94 = /http\:\/\/nemesis\-kb\-http\.default\.svc\.cluster\.local\:5601/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string95 = /http\:\/\/nemesis\-kb\-http\:5601/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string96 = /https\:\/\/nemesis\..{0,1000}\.com\/api\// nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string97 = /logging\.getLogger\(\"nemesis\"\)/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string98 = /modules\/nemesis\.rb/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string99 = /Nemesis\sfrontend\sHTTP\sserver\sendpoint/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string100 = /nemesis\:Qwerty12345\@/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string101 = /nemesis\@nemesis\.com/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string102 = /nemesis\@nemesis\.local/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string103 = /NEMESIS_API_URL/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string104 = /NEMESIS_HTTP_SERVER\s/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string105 = /nemesis_post_file\(/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string106 = /nemesis\-rabbitmq\-discovery/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string107 = /nemesis\-rabbitmq\-discovery\.default\.svc\.cluster\.local/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string108 = /NemesisRabbitMQProducer/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string109 = /plugins\/nemesis\.rb/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string110 = /sample_files\/passwd/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string111 = /Seatbelt\.Commands\.Windows/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string112 = /skaffold\srun\s\-m\snemesis\s/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string113 = /SpecterOps\/Nemesis/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string114 = /Staring\sNemesis\sBot\.\sTeamserver/ nocase ascii wide
        // Description: An offensive data enrichment pipeline
        // Reference: https://github.com/SpecterOps/Nemesis
        $string115 = /webapi\/nemesis_api\.py/ nocase ascii wide

    condition:
        any of them
}
