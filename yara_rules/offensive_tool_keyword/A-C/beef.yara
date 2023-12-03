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
        $string1 = /.{0,1000}\.\/update\-beef.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string2 = /.{0,1000}\/beef\.git.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string3 = /.{0,1000}\/beef\/extensions\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string4 = /.{0,1000}\/beef_bind_shell\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string5 = /.{0,1000}\/beef_common\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string6 = /.{0,1000}\/beefbind\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string7 = /.{0,1000}\/beefproject\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string8 = /.{0,1000}\/bind_powershell\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string9 = /.{0,1000}\/client\/beef\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string10 = /.{0,1000}\/detect_antivirus\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string11 = /.{0,1000}\/detect_antivirus\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string12 = /.{0,1000}\/hijack_opener\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string13 = /.{0,1000}\/hijack_opener\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string14 = /.{0,1000}\/man_in_the_browser\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string15 = /.{0,1000}\/man_in_the_browser\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string16 = /.{0,1000}\/shellcode_sources\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string17 = /.{0,1000}\/simple_hijacker\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string18 = /.{0,1000}\/thirdparty\/msf\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string19 = /.{0,1000}_dns_hijack\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string20 = /.{0,1000}_dns_hijack\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string21 = /.{0,1000}apache_felix_remote_shell.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string22 = /.{0,1000}Applet_ReverseTCP\.jar.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string23 = /.{0,1000}beef:beef.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string24 = /.{0,1000}beef_bind_tcp\-stage\.asm.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string25 = /.{0,1000}beef_bind_tcp\-stager\.asm.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string26 = /.{0,1000}beef_bind\-stage.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string27 = /.{0,1000}beef_bind\-stage\.asm.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string28 = /.{0,1000}beef_bind\-stager\.asm.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string29 = /.{0,1000}beef_test\.rb.{0,1000}/ nocase ascii wide
        // Description: The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string30 = /.{0,1000}beefproject.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string31 = /.{0,1000}beef\-xss.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string32 = /.{0,1000}browser_autopwn.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string33 = /.{0,1000}chromecertbeggar\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string34 = /.{0,1000}chromecertbeggar2\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string35 = /.{0,1000}clickjack_attack\.html.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string36 = /.{0,1000}clickjack_victim\.html.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string37 = /.{0,1000}coldfusion_dir_traversal_exploit.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string38 = /.{0,1000}ContentHijacking\.swf.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string39 = /.{0,1000}csrf_to_beef.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string40 = /.{0,1000}dlink_sharecenter_cmd_exec.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string41 = /.{0,1000}edge_wscript_wsh_injection.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string42 = /.{0,1000}exploit.{0,1000}wordpress_add_admin.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string43 = /.{0,1000}exploits.{0,1000}_csrf\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string44 = /.{0,1000}exploits.{0,1000}_csrf\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string45 = /.{0,1000}extract_cmd_exec.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string46 = /.{0,1000}extract_cmd_exec.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string47 = /.{0,1000}fake_evernote_clipper.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string48 = /.{0,1000}fake_flash_update.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string49 = /.{0,1000}fake_lastpass\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string50 = /.{0,1000}fake_notification_ff\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string51 = /.{0,1000}ff_osx_extension\-dropper.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string52 = /.{0,1000}firefox_extension_bindshell.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string53 = /.{0,1000}firefox_extension_reverse_shell.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string54 = /.{0,1000}freenas_reverse_root_shell_csrf.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string55 = /.{0,1000}glassfish_war_upload_xsrf.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string56 = /.{0,1000}hookedbrowsers\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string57 = /.{0,1000}http.{0,1000}\/demos\/butcher\/index\.html.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string58 = /.{0,1000}http.{0,1000}:3000\/hook\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string59 = /.{0,1000}http:\/\/127\.0\.0\.1:3000\/ui\/panel.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string60 = /.{0,1000}http:\/\/localhost:3000\/ui\/panel.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string61 = /.{0,1000}ie_win_fakenotification\-clippy.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string62 = /.{0,1000}ie_win_htapowershell\..{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string63 = /.{0,1000}ie_win_missingflash\-prettytheft.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string64 = /.{0,1000}jboss_jmx_upload_exploit.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string65 = /.{0,1000}lan_fingerprint_common\..{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string66 = /.{0,1000}lan_ping_sweep\.json.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string67 = /.{0,1000}lan_sw_port_scan\.json.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string68 = /.{0,1000}man_in_the_browser\.json.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string69 = /.{0,1000}modules\/exploits\/.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string70 = /.{0,1000}modules\/exploits\/.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string71 = /.{0,1000}pfsense.{0,1000}reverse_root_shell_csrf\/.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string72 = /.{0,1000}portscanner\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string73 = /.{0,1000}replace_video_fake_plugin.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string74 = /.{0,1000}ruby_nntpd_cmd_exec.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string75 = /.{0,1000}shell_shocked.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string76 = /.{0,1000}shell_shocked.{0,1000}\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string77 = /.{0,1000}social_engineering\/web_cloner.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string78 = /.{0,1000}spring_framework_malicious_jar.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string79 = /.{0,1000}test_beef_debugs_spec.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string80 = /.{0,1000}vtiger_crm_upload_exploit.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string81 = /.{0,1000}web_cloner\/interceptor.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string82 = /.{0,1000}wifi_pineapple_csrf.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string83 = /.{0,1000}win_fake_malware\..{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string84 = /.{0,1000}xssrays\.js.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string85 = /.{0,1000}xssrays\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string86 = /.{0,1000}xssrays_spec\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string87 = /.{0,1000}xssraysdetail\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string88 = /.{0,1000}xssraysscan\.rb.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string89 = /.{0,1000}zenoss_3x_command_execution.{0,1000}/ nocase ascii wide
        // Description: BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.
        // Reference: https://github.com/beefproject/beef
        $string90 = /\.\/beef/ nocase ascii wide

    condition:
        any of them
}
