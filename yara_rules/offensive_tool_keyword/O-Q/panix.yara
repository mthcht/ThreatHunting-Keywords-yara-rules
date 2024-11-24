rule panix
{
    meta:
        description = "Detection patterns for the tool 'panix' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "panix"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string1 = " --backdoor-user " nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string2 = " --malicious-package " nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string3 = /\spanix\.sh\s\-\-/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string4 = /\spanix\.sh\s\-\-generator/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string5 = /\spanix\.sh\s\-\-generator/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string6 = /\spanix\.sh\s\-\-systemd/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string7 = " --sudoers-backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string8 = /\#\!\/bin\/bash\\n\/bin\/bash\s\-c\s\'sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string9 = /\.sh\s\-\-at\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-time\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string10 = /\.sh\s\-\-authorized\-keys\s\-\-custom\s\-\-key\s.{0,1000}\.ssh\/authorized_keys/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string11 = /\.sh\s\-\-backdoor\-user\s\-\-username\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string12 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-crond\s\-\-name\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string13 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-crontab/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string14 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-daily\s\-\-name\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string15 = /\.sh\s\-\-passwd\-user\s\-\-custom\s\-\-passwd\-string\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string16 = /\.sh\s\-\-shell\-profile\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-path\s.{0,1000}\/\.bash_profile/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string17 = /\.sh\s\-\-systemd\s\-\-custom\s\-\-command\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string18 = /\.sh\s\-\-systemd\s\-\-default\s\-\-ip\s.{0,1000}\s\-\-port\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string19 = /\.sh\s\-\-udev\s\-\-custom\s\-\-command\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string20 = /\.sh\s\-\-xdg\s\-\-custom\s\-\-command\s.{0,1000}\s\-\-path\s.{0,1000}\/etc\/xdg\/autostart\// nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string21 = /\/etc\/xdg\/autostart\/evilxdg\.desktop/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string22 = /\/lib\/systemd\/system\/evil\.service/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string23 = /\/PANIX\.git/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string24 = /\/panix\.sh\s\-\-/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string25 = /\/releases\/download\/panix\-v.{0,1000}\/panix\.sh/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string26 = "/usr/bin/at -M -f /tmp/payload" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string27 = "/usr/bin/at -M -f /usr/bin/atest" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string28 = /\/usr\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/\$ip\/\$port\s0\>\&1/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string29 = /\/usr\/local\/bin\/escape\.sh/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string30 = ":0:0:root:/root:/bin/bash\" >> /etc/passwd" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string31 = /\[\-\]\sFailed\sto\screate\ssudoers\sbackdoor\sfor\suser\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string32 = /\[\+\]\s\$bin\sbackdoored\ssuccessful/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string33 = /\[\+\]\s\$binary\sbackdoored\ssuccessful/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string34 = /\[\+\]\s\/etc\/passwd\spersistence\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string35 = /\[\+\]\sAPT\spersistence\sestablis/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string36 = /\[\+\]\sAt\sjob\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string37 = /\[\+\]\sAuthorized_keys\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string38 = /\[\+\]\sBackdoor\suser\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string39 = /\[\+\]\sBackdoor\suser\spersistence\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string40 = /\[\+\]\sBind\sshell\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string41 = /\[\+\]\sCapabilities\sbackdoor\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string42 = /\[\+\]\sCreated\smalicious\spre\-commit\shook\sin\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string43 = /\[\+\]\sCron\spersistence\sestablished/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string44 = /\[\+\]\sDocker\scontainer\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string45 = /\[\+\]\sGit\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string46 = /\[\+\]\sinit\.d\sbackdoor\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string47 = /\[\+\]\sMOTD\sbackdoor\spersistence\sestablish/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string48 = /\[\+\]\sRemoved\smalicious\sentry\sfrom\spre\-commit\shook\sin\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string49 = /\[\+\]\sSSH\skey\spersistence\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string50 = /\[\+\]\sSystemd\sGenerator\spersistence\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string51 = /\[\+\]\sUser\s.{0,1000}\sadded\sto\s\/etc\/passwd\swith\sroot\sprivileges\./ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string52 = /\[\+\]\sUser\s.{0,1000}\shas\sbeen\smodified\sto\shave\sUID\s0\s\(root\sprivileges\)\./ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string53 = /\[\+\]\sUser\spersistence\sthrough\sthe\snew\s.{0,1000}\suser\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string54 = /\[\+\]\sXDG\spersistence\sestablished\!/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string55 = /\]\sCleaning\sAt\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string56 = /\]\sCleaning\sBackdoor\sbinaries\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string57 = /\]\sCleaning\sBind\sshell\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string58 = /\]\sCleaning\sCron\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string59 = /\]\sCleaning\sDocker\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string60 = /\]\sCleaning\sGit\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string61 = /\]\sCleaning\sinitd\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string62 = /\]\sCleaning\sMalicious\spackage\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string63 = /\]\sCleaning\sMOTD\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string64 = /\]\sCleaning\sPackage\sManagers\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string65 = /\]\sCleaning\src\.local\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string66 = /\]\sCleaning\ssetcap\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string67 = /\]\sCleaning\sSetuid\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string68 = /\]\sCleaning\sShell\sprofile\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string69 = /\]\sCleaning\sSSH\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string70 = /\]\sCleaning\sSudoers\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string71 = /\]\sCleaning\sSystemd\sGenerator\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string72 = /\]\sCleaning\sSystemd\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string73 = /\]\sCleaning\sudev\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string74 = /\]\sCleaning\sXDG\spersistence\smethods/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string75 = "7cd720218d9cf22a1143274f4904f30bcef18bfc00ebb54de45bedfeb12d1535" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string76 = "8c842d7dfb5c081a394e645377db303da5228ee78ff9467c4f00534ba8e0c389" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string77 = "974cf826367e6b3bd96006f325a549d892da924bf76afc7df546e31ede536696" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string78 = "add_malicious_pager" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string79 = "add_malicious_pre_commit" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string80 = "Aegrah/PANIX" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string81 = "c3663dba552ca6aa8d2c0f36fccc553d728b37464944080398f72f487430710f" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string82 = /cat\s.{0,1000}\.pub\s\>\>\s.{0,1000}\/authorized_keys/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string83 = "cat <<-EOF > /usr/lib/systemd/system-generators/generator" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string84 = /chmod\s\+x\s\/usr\/lib\/systemd\/system\-generators\/makecon/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string85 = "echo \"@RFGroenewoud\"" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string86 = "f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiiAAAA8AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2AW15SaAIAIylqEFFQieFqZljNgIlBBLMEsGbNgEOwZs2Ak1lqP1jNgEl5" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string87 = "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgAjKUiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string88 = /ln\s\-s\s\/run\/systemd\/system\/generator\.service\s\/run\/systemd\/system\/multi\-user\.target\.wants\/generator\.service/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string89 = /nohup\sbash\s\-c\s\\"while\s\:\;\sdo\sbash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\;\ssleep\s10\;\sdone/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string90 = /panix\.sh\s\-\-ssh\-key\s/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string91 = "setup_backdoor_user" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string92 = "setup_cap_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string93 = "setup_generator_persistence" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string94 = "setup_git_persistence" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string95 = "setup_initd_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string96 = "setup_malicious_docker_container" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string97 = "setup_malicious_package" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string98 = "setup_motd_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string99 = "setup_rc_local_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string100 = "setup_sudoers_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string101 = "setup_suid_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string102 = "setup_system_binary_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string103 = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/1337\s0\>\&1/ nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string104 = "sudo nsenter -t 1 -m -u -i -n -p -- su -" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string105 = "usage_backdoor_user" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string106 = "usage_initd_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string107 = "usage_malicious_docker_container" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string108 = "usage_malicious_package" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string109 = "usage_motd_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string110 = "usage_package_manager_persistence" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string111 = "usage_rc_local_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string112 = "usage_sudoers_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string113 = "usage_suid_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string114 = "usage_system_binary_backdoor" nocase ascii wide
        // Description: PANIX is a highly customizable Linux persistence tool
        // Reference: https://github.com/Aegrah/PANIX
        $string115 = "usermod -u 0 -o " nocase ascii wide

    condition:
        any of them
}
