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
        $string1 = /.{0,1000}\s\-\-pacu\-help.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string2 = /.{0,1000}\/\.local\/share\/pacu\/.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string3 = /.{0,1000}\/acm_enum_cas_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string4 = /.{0,1000}\/acm_enum_certs_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string5 = /.{0,1000}\/acm_enum_certs_chain_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string6 = /.{0,1000}\/acm_enum_certs_expired_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string7 = /.{0,1000}\/acm_enum_certs_info_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string8 = /.{0,1000}\/aws__enum_account.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string9 = /.{0,1000}\/aws__enum_account\/main\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string10 = /.{0,1000}\/backdoor_all_users\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string11 = /.{0,1000}\/cfn__resource_injection_lambda.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string12 = /.{0,1000}\/cmd_log\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string13 = /.{0,1000}\/ec2__backdoor_ec2_sec_groups.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string14 = /.{0,1000}\/ec2__check_termination_protection.{0,1000}\.py/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string15 = /.{0,1000}\/ec2__startup_shell_script\/main\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string16 = /.{0,1000}\/ec2_public_ips_.{0,1000}_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string17 = /.{0,1000}\/enum__secrets\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string18 = /.{0,1000}\/iam__backdoor_users_password.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string19 = /.{0,1000}\/iam__bruteforce_permissions\/.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string20 = /.{0,1000}\/iam__privesc_scan.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string21 = /.{0,1000}\/lambda__backdoor_new_roles.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string22 = /.{0,1000}\/lambda__backdoor_new_sec_groups.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string23 = /.{0,1000}\/lambda__backdoor_new_users.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string24 = /.{0,1000}\/pacu\.git.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string25 = /.{0,1000}\/vpc__enum_lateral_movement.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string26 = /.{0,1000}\/waf__enum\/main\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string27 = /.{0,1000}\=MSEXCEL.{0,1000}regsvr32\s\/s\s\/n\s\/u\s\/i:http.{0,1000}\/SCTLauncher\.sct\sscrobj\.dll.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string28 = /.{0,1000}cloudtrail__csv_injection.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string29 = /.{0,1000}docker\srun\s.{0,1000}\/pacu:latest.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string30 = /.{0,1000}ecs_task_def_data\/all_task_def\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string31 = /.{0,1000}iam__enum_assume_role\/default\-word\-list\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string32 = /.{0,1000}lambda__backdoor_new_sec_groups.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string33 = /.{0,1000}pacu\s\-\-exec\s.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string34 = /.{0,1000}pacu\s\-\-list\-modules.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string35 = /.{0,1000}pacu\s\-\-module\-args\=.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string36 = /.{0,1000}pacu\s\-\-module\-info.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string37 = /.{0,1000}pacu\s\-\-module\-name\s.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string38 = /.{0,1000}pacu\s\-\-session\s.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string39 = /.{0,1000}pacu\s\-\-set\-regions\s.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string40 = /.{0,1000}pacu\s\-\-whoami.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string41 = /.{0,1000}pacu\/core\spacu.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string42 = /.{0,1000}pacu\/last_update\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string43 = /.{0,1000}pacu\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string44 = /.{0,1000}pip3\sinstall\s\-U\spacu.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string45 = /.{0,1000}python3\spacu\.py.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string46 = /.{0,1000}RhinoSecurityLabs\/pacu.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string47 = /.{0,1000}secrets\/secrets_manager\/secrets\.txt.{0,1000}/ nocase ascii wide
        // Description: The AWS exploitation framework designed for testing the security of Amazon Web Services environments.
        // Reference: https://github.com/RhinoSecurityLabs/pacu
        $string48 = /.{0,1000}test_pacu_update\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
