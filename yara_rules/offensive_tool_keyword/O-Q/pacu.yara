rule pacu
{
    meta:
        description = "Detection patterns for the tool 'pacu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pacu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string1 = /\s\-\-pacu\-help/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string2 = /\/\.local\/share\/pacu\// nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string3 = /\/acm_enum_cas_.{0,1000}\.json/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string4 = /\/acm_enum_certs_.{0,1000}\.json/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string5 = /\/acm_enum_certs_chain_.{0,1000}\.json/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string6 = /\/acm_enum_certs_expired_.{0,1000}\.json/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string7 = /\/acm_enum_certs_info_.{0,1000}\.json/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string8 = /\/aws__enum_account/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string9 = /\/aws__enum_account\/main\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string10 = /\/backdoor_all_users\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string11 = /\/cfn__resource_injection_lambda/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string12 = /\/cmd_log\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string13 = /\/ec2__backdoor_ec2_sec_groups/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string14 = /\/ec2__check_termination_protection.{0,1000}\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string15 = /\/ec2__startup_shell_script\/main\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string16 = /\/ec2_public_ips_.{0,1000}_.{0,1000}\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string17 = /\/enum__secrets\/.{0,1000}\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string18 = /\/iam__backdoor_users_password/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string19 = /\/iam__bruteforce_permissions\// nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string20 = /\/iam__privesc_scan/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string21 = /\/lambda__backdoor_new_roles/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string22 = /\/lambda__backdoor_new_sec_groups/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string23 = /\/lambda__backdoor_new_users/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string24 = /\/pacu\.git/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string25 = /\/vpc__enum_lateral_movement/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string26 = /\/waf__enum\/main\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string27 = /\=MSEXCEL.{0,1000}regsvr32\s\/s\s\/n\s\/u\s\/i\:http.{0,1000}\/SCTLauncher\.sct\sscrobj\.dll/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string28 = /cloudtrail__csv_injection/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string29 = /docker\srun\s.{0,1000}\/pacu\:latest/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string30 = /ecs_task_def_data\/all_task_def\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string31 = /iam__enum_assume_role\/default\-word\-list\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string32 = /lambda__backdoor_new_sec_groups/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string33 = /pacu\s\-\-exec\s/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string34 = /pacu\s\-\-list\-modules/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string35 = /pacu\s\-\-module\-args\=/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string36 = /pacu\s\-\-module\-info/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string37 = /pacu\s\-\-module\-name\s/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string38 = /pacu\s\-\-session\s/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string39 = /pacu\s\-\-set\-regions\s/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string40 = /pacu\s\-\-whoami/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string41 = /pacu\/core\spacu/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string42 = /pacu\/last_update\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string43 = /pacu\-master\.zip/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string44 = /pip3\sinstall\s\-U\spacu/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string45 = /python3\spacu\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string46 = /RhinoSecurityLabs\/pacu/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string47 = /secrets\/secrets_manager\/secrets\.txt/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string48 = /test_pacu_update\.py/ nocase ascii wide

    condition:
        any of them
}
