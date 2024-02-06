rule beef
{
    meta:
        description = "Detection patterns for the tool 'beef' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "beef"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string1 = /\.\/update\-beef/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string2 = /\/beef\.git/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string3 = /\/beef\/extensions\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string4 = /\/beef_bind_shell\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string5 = /\/beef_common\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string6 = /\/beefbind\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string7 = /\/beefproject\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string8 = /\/bind_powershell\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string9 = /\/client\/beef\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string10 = /\/detect_antivirus\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string11 = /\/detect_antivirus\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string12 = /\/hijack_opener\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string13 = /\/hijack_opener\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string14 = /\/man_in_the_browser\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string15 = /\/man_in_the_browser\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string16 = /\/shellcode_sources\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string17 = /\/simple_hijacker\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string18 = /\/thirdparty\/msf\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string19 = /_dns_hijack\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string20 = /_dns_hijack\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string21 = /apache_felix_remote_shell/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string22 = /Applet_ReverseTCP\.jar/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string23 = /beef\:beef/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string24 = /beef_bind_tcp\-stage\.asm/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string25 = /beef_bind_tcp\-stager\.asm/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string26 = /beef_bind\-stage.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string27 = /beef_bind\-stage\.asm/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string28 = /beef_bind\-stager\.asm/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string29 = /beef_test\.rb/ nocase ascii wide
        // Description: The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string30 = /beefproject/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string31 = /beef\-xss/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string32 = /browser_autopwn/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string33 = /chromecertbeggar\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string34 = /chromecertbeggar2\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string35 = /clickjack_attack\.html/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string36 = /clickjack_victim\.html/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string37 = /coldfusion_dir_traversal_exploit/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string38 = /ContentHijacking\.swf/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string39 = /csrf_to_beef/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string40 = /dlink_sharecenter_cmd_exec/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string41 = /edge_wscript_wsh_injection/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string42 = /exploit.{0,1000}wordpress_add_admin/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string43 = /exploits.{0,1000}_csrf\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string44 = /exploits.{0,1000}_csrf\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string45 = /extract_cmd_exec.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string46 = /extract_cmd_exec.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string47 = /fake_evernote_clipper/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string48 = /fake_flash_update/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string49 = /fake_lastpass\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string50 = /fake_notification_ff\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string51 = /ff_osx_extension\-dropper/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string52 = /firefox_extension_bindshell/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string53 = /firefox_extension_reverse_shell/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string54 = /freenas_reverse_root_shell_csrf/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string55 = /glassfish_war_upload_xsrf/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string56 = /hookedbrowsers\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string57 = /http.{0,1000}\/demos\/butcher\/index\.html/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string58 = /http.{0,1000}\:3000\/hook\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string59 = /http\:\/\/127\.0\.0\.1\:3000\/ui\/panel/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string60 = /http\:\/\/localhost\:3000\/ui\/panel/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string61 = /ie_win_fakenotification\-clippy/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string62 = /ie_win_htapowershell\./ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string63 = /ie_win_missingflash\-prettytheft/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string64 = /jboss_jmx_upload_exploit/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string65 = /lan_fingerprint_common\./ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string66 = /lan_ping_sweep\.json/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string67 = /lan_sw_port_scan\.json/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string68 = /man_in_the_browser\.json/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string69 = /modules\/exploits\/.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string70 = /modules\/exploits\/.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string71 = /pfsense.{0,1000}reverse_root_shell_csrf\// nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string72 = /portscanner\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string73 = /replace_video_fake_plugin/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string74 = /ruby_nntpd_cmd_exec/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string75 = /shell_shocked.{0,1000}\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string76 = /shell_shocked.{0,1000}\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string77 = /social_engineering\/web_cloner/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string78 = /spring_framework_malicious_jar/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string79 = /test_beef_debugs_spec/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string80 = /vtiger_crm_upload_exploit/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string81 = /web_cloner\/interceptor/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string82 = /wifi_pineapple_csrf/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string83 = /win_fake_malware\./ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string84 = /xssrays\.js/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string85 = /xssrays\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string86 = /xssrays_spec\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string87 = /xssraysdetail\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string88 = /xssraysscan\.rb/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string89 = /zenoss_3x_command_execution/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string90 = /\.\/beef/ nocase ascii wide

    condition:
        any of them
}
