© 2025 Sentrilite, Inc. All rights reserved.
“Sentrilite” and related marks are trademarks of Sentrilite, Inc. Other names may be trademarks of their respective owners.

# Security Rules Summary 

## Overview

This document provides a comprehensive summary of all security rules available in the system. The rules are organized into two main categories: **Pod Rules** (Kubernetes pod security configurations) and **Host Rules** (host-level security configurations).

**Total Rules: 312**
- **Pod Rules: 98**
- **Host Rules: 214**

---

## POD RULES (98 Rules)

### Service Account & Authentication (3 rules)
1. **default_sa_used** - Detects pods using the default service account or no service account. Using default service accounts can lead to privilege escalation risks.
2. **automount_service_account_token_true** - Checks for pods that automatically mount service account tokens. This can expose service account credentials unnecessarily if not required.
3. **service_account_automount_token_true** - Identifies service accounts with automatic token mounting enabled.

### Namespace & Isolation (1 rule)
4. **workload_in_default_namespace** - Identifies workloads running in the default namespace. The default namespace should be avoided for production workloads to improve isolation and security.

### Network Configuration (3 rules)
5. **dns_policy_default** - Checks for pods using the default DNS policy. Default DNS policy may not provide proper DNS resolution in all cluster configurations.
6. **host_network_enabled** - Detects pods with hostNetwork enabled. This allows the pod to access the host's network stack, bypassing network isolation and increasing attack surface.
7. **host_port_used** - Identifies pods using host ports. This bypasses Kubernetes service networking and can cause port conflicts.

### Process & IPC Isolation (3 rules)
8. **host_pid_enabled** - Identifies pods with hostPID enabled. This allows the pod to see all processes on the host, potentially exposing sensitive information.
9. **host_ipc_enabled** - Detects pods with hostIPC enabled. This allows the pod to access the host's IPC namespace, potentially enabling inter-process communication with host processes.
10. **share_process_namespace_enabled** - Identifies pods with shared process namespace enabled. This allows containers in the pod to see each other's processes, reducing isolation.

### HostPath Volume Mounts (12 rules)
11. **hostpath_root** - Detects pods mounting the root filesystem via hostPath. This provides unrestricted access to the host filesystem and is a critical security risk.
12. **hostpath_etc** - Identifies pods mounting /etc directory via hostPath. This exposes host system configuration files and can lead to privilege escalation.
13. **hostpath_root_dir** - Detects pods mounting /root directory via hostPath. This exposes the root user's home directory and sensitive files.
14. **hostpath_var_lib** - Checks for pods mounting /var/lib via hostPath. This directory contains application data and can expose sensitive information.
15. **hostpath_var_run** - Identifies pods mounting /var/run via hostPath. This directory contains runtime data and socket files that should be isolated.
16. **hostpath_var_lib_kubelet** - Detects pods mounting /var/lib/kubelet via hostPath. This exposes Kubernetes node configuration and can compromise cluster security.
17. **hostpath_proc** - Checks for pods mounting /proc via hostPath. This exposes host process information and kernel parameters, reducing isolation.
18. **hostpath_sys** - Identifies pods mounting /sys via hostPath. This exposes kernel and system information, potentially allowing host manipulation.
19. **hostpath_dev** - Detects pods mounting /dev via hostPath. This provides access to host device files and can enable device-level attacks.
20. **hostpath_dev_shm** - Checks for pods mounting /dev/shm via hostPath. This shared memory filesystem can be used for inter-process communication with the host.
21. **hostpath_var_run_docker_sock** - Identifies pods mounting Docker socket via hostPath. This provides full Docker daemon access and can lead to container escape.
22. **hostpath_run_containerd_containerd_sock** - Detects pods mounting containerd socket via hostPath. This provides full containerd access and can enable container escape attacks.

### Container Security Context (5 rules)
23. **container_privileged_true** - Detects containers running in privileged mode. Privileged containers have access to all host devices and capabilities, significantly increasing security risk.
24. **run_as_non_root_false_or_missing** - Checks if containers are configured to run as non-root user. Running as root increases the impact of container compromise.
25. **allow_privilege_escalation_true** - Identifies containers that allow privilege escalation. This enables processes to gain additional privileges beyond their initial set.
26. **read_only_root_fs_disabled** - Detects containers with writable root filesystem. Read-only root filesystems prevent malicious writes and improve security.
27. **run_as_user_0** - Identifies containers configured to run as root user (UID 0). This increases security risk if the container is compromised.

### Linux Capabilities (37 rules)
28. **cap_drop_missing_all** - Checks if containers drop all capabilities. Containers should drop all unnecessary capabilities to follow the principle of least privilege.
29. **cap_add_sys_admin** - Detects containers with SYS_ADMIN capability. This provides extensive system administration privileges and is highly dangerous.
30. **cap_add_net_admin** - Identifies containers with NET_ADMIN capability. This allows network configuration changes and can be used for network attacks.
31. **cap_add_sys_ptrace** - Checks for containers with SYS_PTRACE capability. This allows debugging and tracing of processes, potentially exposing sensitive information.
32. **cap_add_sys_module** - Detects containers with SYS_MODULE capability. This allows loading and unloading kernel modules, which is a significant security risk.
33. **cap_add_sys_time** - Identifies containers with SYS_TIME capability. This allows modification of system time.
34. **cap_add_sys_rawio** - Checks for containers with SYS_RAWIO capability. This provides access to raw I/O ports and memory.
35. **cap_add_mknod** - Detects containers with MKNOD capability. This allows creation of special device files.
36. **cap_add_audit_control** - Identifies containers with AUDIT_CONTROL capability. This allows configuration of kernel audit system.
37. **cap_add_syslog** - Checks for containers with SYSLOG capability. This allows configuration of kernel syslog.
38. **cap_add_dac_read_search** - Detects containers with DAC_READ_SEARCH capability. This bypasses file read and directory search permission checks.
39. **cap_add_dac_override** - Identifies containers with DAC_OVERRIDE capability. This bypasses file read, write, and execute permission checks.
40. **cap_add_linux_immutable** - Checks for containers with LINUX_IMMUTABLE capability. This allows modification of immutable files.
41. **cap_add_net_raw** - Detects containers with NET_RAW capability. This allows creation of raw sockets for network attacks.
42. **cap_add_net_broadcast** - Identifies containers with NET_BROADCAST capability. This allows broadcasting network packets.
43. **cap_add_fowner** - Checks for containers with FOWNER capability. This bypasses permission checks for file ownership.
44. **cap_add_chown** - Detects containers with CHOWN capability. This allows changing file ownership.
45. **cap_add_setgid** - Identifies containers with SETGID capability. This allows manipulation of process group IDs.
46. **cap_add_setuid** - Checks for containers with SETUID capability. This allows manipulation of process user IDs.
47. **cap_add_setfcap** - Detects containers with SETFCAP capability. This allows setting file capabilities.
48. **cap_add_setpcap** - Identifies containers with SETPCAP capability. This allows manipulation of process capabilities.
49. **cap_add_sys_boot** - Checks for containers with SYS_BOOT capability. This allows rebooting the system.
50. **cap_add_sys_nice** - Detects containers with SYS_NICE capability. This allows modification of process priorities.
51. **cap_add_ipc_lock** - Identifies containers with IPC_LOCK capability. This allows locking memory pages.
52. **cap_add_ipc_owner** - Checks for containers with IPC_OWNER capability. This bypasses permission checks for System V IPC objects.
53. **cap_add_lease** - Detects containers with LEASE capability. This allows taking leases on files.
54. **cap_add_sys_resource** - Identifies containers with SYS_RESOURCE capability. This allows overriding resource limits.
55. **cap_add_sys_tty_config** - Checks for containers with SYS_TTY_CONFIG capability. This allows configuration of TTY devices.
56. **cap_add_wake_alarm** - Detects containers with WAKE_ALARM capability. This allows setting wake alarms.
57. **cap_add_sys_pacct** - Identifies containers with SYS_PACCT capability. This allows configuration of process accounting.
58. **cap_add_mac_admin** - Checks for containers with MAC_ADMIN capability. This allows configuration of Mandatory Access Control.

### Seccomp & Security Profiles (2 rules)
59. **seccomp_profile_missing_or_unset** - Detects containers without seccomp profile configured. Seccomp profiles restrict system calls and improve security.
60. **pod_seccomp_missing_or_unset** - Identifies pods without seccomp profile configured at the pod level.

### Health Checks & Probes (3 rules)
61. **liveness_probe_missing** - Detects containers without liveness probes. Liveness probes help Kubernetes restart unhealthy containers.
62. **readiness_probe_missing** - Identifies containers without readiness probes. Readiness probes ensure traffic is only sent to ready containers.
63. **startup_probe_missing** - Checks for containers without startup probes. Startup probes help manage containers with slow startup times.

### Resource Limits & Requests (6 rules)
64. **limits_cpu_missing** - Detects containers without CPU limits. CPU limits prevent resource exhaustion and ensure fair resource allocation.
65. **limits_memory_missing** - Identifies containers without memory limits. Memory limits prevent memory exhaustion and OOM kills.
66. **limits_ephemeral_storage_missing** - Checks for containers without ephemeral storage limits.
67. **requests_cpu_missing** - Detects containers without CPU requests. CPU requests help with proper scheduling and resource planning.
68. **requests_memory_missing** - Identifies containers without memory requests.
69. **requests_ephemeral_storage_missing** - Checks for containers without ephemeral storage requests.

### Image Security (2 rules)
70. **image_without_digest** - Detects container images specified without digest. Images without digests can lead to unexpected updates.
71. **image_tag_latest_or_missing** - Identifies containers using 'latest' tag or no tag. This can lead to unpredictable deployments.

### Pod Security Context (5 rules)
72. **pod_security_context_missing** - Detects pods without security context. Security contexts define privilege and access control settings.
73. **run_as_group_0** - Identifies pods configured to run as root group (GID 0).
74. **fs_group_not_set** - Checks for pods without fsGroup set. fsGroup ensures volumes are owned by the specified group.
75. **supplemental_groups_present** - Detects pods with supplemental groups configured. This can grant additional file access permissions.
76. **proc_mount_default** - Identifies pods using default /proc mount. Default /proc mounts expose more information than necessary.

### Configuration & Secrets (5 rules)
77. **secrets_in_env_from_secretkeyref** - Detects secrets referenced in envFrom. This can expose secrets unnecessarily.
78. **env_vars_from_configmap** - Identifies environment variables loaded from ConfigMaps.
79. **env_vars_plaintext** - Detects plaintext environment variables. Sensitive data should be stored in secrets, not plaintext env vars.
80. **configmap_mounted** - Checks for ConfigMaps mounted as volumes.
81. **secret_mounted** - Identifies secrets mounted as volumes.

### Volume Security (4 rules)
82. **volume_mounts_writable** - Detects writable volume mounts. Read-only mounts improve security by preventing unauthorized writes.
83. **empty_dir_volume_present** - Identifies pods using emptyDir volumes. EmptyDir volumes can consume node disk space.
84. **downward_api_volume_present** - Detects pods using downward API volumes. This exposes pod metadata to containers.

### Lifecycle & Scheduling (8 rules)
85. **termination_grace_period_too_long** - Identifies pods with excessively long termination grace periods.
86. **lifecycle_hooks_missing** - Detects containers without lifecycle hooks. Lifecycle hooks help with graceful shutdowns.
87. **restart_policy_always** - Checks for pods with restart policy set to Always. This may not be appropriate for all workloads.
88. **priority_class_missing** - Detects pods without priority class. Priority classes help with pod scheduling and eviction.
89. **node_selector_missing** - Identifies pods without node selectors. Node selectors help control pod placement.
90. **tolerations_present** - Detects pods with tolerations. Tolerations allow pods to run on tainted nodes.
91. **affinity_missing** - Checks for pods without affinity rules. Affinity rules help optimize pod placement.
92. **topology_spread_constraints_missing** - Identifies pods without topology spread constraints. This helps distribute pods across zones/nodes.

### Advanced Configuration (6 rules)
93. **sysctls_unsafe_present** - Detects pods with unsafe sysctls. Unsafe sysctls can affect node stability.
94. **image_pull_policy_always_missing** - Identifies containers without imagePullPolicy set to Always. This ensures latest images are pulled.
95. **dns_config_custom** - Detects pods with custom DNS configuration.
96. **host_aliases_present** - Identifies pods with host aliases configured.
97. **runtime_class_missing** - Checks for pods without runtime class specified.
98. **overhead_resources_missing** - Detects pods without overhead resources defined.

---

## HOST RULES (214 Rules)

### File System Security (3 rules)
1. **ww_files_etc** - Detects world-writable files in /etc directory. World-writable files can be modified by any user, creating security risks.
2. **ww_files_home** - Identifies world-writable files in /home directories. This can allow unauthorized access to user data.
3. **ww_files_var** - Detects world-writable files in /var directory. This can expose system and application data.

### Network Listeners (2 rules)
4. **public_tcp_listeners** - Identifies TCP services listening on public interfaces. This exposes services to network attacks.
5. **public_udp_listeners** - Detects UDP services listening on public interfaces. This can expose services to network attacks.

### Firewall & Network Security (4 rules)
6. **ufw_inactive** - Detects inactive UFW (Uncomplicated Firewall). Firewalls are essential for network security.
7. **firewalld_inactive** - Identifies inactive firewalld. Firewalls help protect against unauthorized network access.
8. **iptables_permissive** - Checks for permissive iptables rules. Permissive rules can allow unauthorized network access.
9. **selinux_not_enforcing** - Detects systems where SELinux is not in enforcing mode. SELinux provides mandatory access control.

### System Security Services (2 rules)
10. **auditd_inactive** - Identifies inactive auditd service. Audit logging is essential for security monitoring and compliance.
11. **apparmor_disabled** - Detects disabled AppArmor. AppArmor provides application-level security policies.

### Kernel & System Configuration (2 rules)
12. **kernel_modules_autoload_enabled** - Detects enabled kernel module autoloading. This can allow loading of malicious kernel modules.
13. **core_dumps_enabled** - Identifies systems with core dumps enabled. Core dumps can expose sensitive memory contents.

### IPv6 Configuration (1 rule)
14. **ipv6_enabled** - Detects enabled IPv6. IPv6 should be disabled if not in use to reduce attack surface.

### ICMP Configuration (4 rules)
15. **icmp_redirects_enabled** - Detects enabled ICMP redirects. ICMP redirects can be used for man-in-the-middle attacks.
16. **icmp_echo_ignore_broadcasts_disabled** - Identifies systems not ignoring ICMP echo broadcasts. This can be used for network scanning.
17. **icmp_ignore_bogus_error_responses_disabled** - Detects systems not ignoring bogus ICMP error responses. This can be exploited for attacks.
18. **icmp_ratelimit_high** - Checks for high ICMP rate limits. High limits can allow ICMP flood attacks.

### IP Forwarding & Routing (5 rules)
19. **source_routing_enabled** - Detects enabled source routing. Source routing can be used for network attacks.
20. **ip_forward_enabled** - Identifies enabled IP forwarding. IP forwarding should be disabled on non-router systems.
21. **send_redirects_enabled** - Detects enabled send redirects. Send redirects can be used for network attacks.
22. **accept_redirects_enabled** - Identifies systems accepting ICMP redirects. This can be used for routing attacks.
23. **secure_redirects_disabled** - Checks for disabled secure redirects. Secure redirects provide safer routing updates.

### TCP/IP Stack Security (100+ rules)

#### SYN Flood Protection (3 rules)
24. **syn_cookies_disabled** - Detects disabled SYN cookies. SYN cookies protect against SYN flood attacks.
25. **tcp_syncookies_disabled** - Identifies disabled TCP SYN cookies. This leaves systems vulnerable to SYN flood attacks.
26. **tcp_syncookies_disabled_final** - Final check for disabled TCP SYN cookies.

#### Reverse Path Filtering (3 rules)
27. **rp_filter_disabled** - Detects disabled reverse path filtering. RPF helps prevent IP spoofing attacks.
28. **rp_filter_disabled_all** - Checks for disabled RPF on all interfaces.
29. **log_martians_disabled** - Identifies disabled logging of martian packets. This reduces visibility into spoofing attempts.
30. **log_martians_disabled_all** - Checks for disabled martian packet logging on all interfaces.

#### TCP Timestamps & Options (10 rules)
31. **tcp_timestamps_enabled** - Detects enabled TCP timestamps. Timestamps can be used for host fingerprinting.
32. **tcp_timestamps_enabled_final** - Final check for enabled TCP timestamps.
33. **tcp_sack_enabled** - Identifies enabled TCP SACK (Selective Acknowledgment). SACK can be exploited in some attacks.
34. **tcp_sack_enabled_all** - Checks for enabled SACK on all interfaces.
35. **tcp_sack_enabled_final** - Final check for enabled TCP SACK.
36. **tcp_window_scaling_enabled** - Detects enabled TCP window scaling. This can be used for fingerprinting.
37. **tcp_window_scaling_enabled_final** - Final check for enabled TCP window scaling.
38. **tcp_ecn_enabled** - Identifies enabled TCP ECN (Explicit Congestion Notification).
39. **tcp_ecn_enabled_final** - Final check for enabled TCP ECN.
40. **tcp_fack_enabled** - Detects enabled TCP FACK (Forward Acknowledgment).
41. **tcp_fack_enabled_final** - Final check for enabled TCP FACK.
42. **tcp_dsack_enabled** - Identifies enabled TCP DSACK (Duplicate Selective Acknowledgment).
43. **tcp_dsack_enabled_final** - Final check for enabled TCP DSACK.

#### TCP Connection Management (20 rules)
44. **tcp_syn_retries_high** - Detects high TCP SYN retry count. High retries can be exploited for SYN flood attacks.
45. **tcp_syn_retries_high_final** - Final check for high TCP SYN retries.
46. **tcp_synack_retries_high** - Identifies high TCP SYN-ACK retry count.
47. **tcp_synack_retries_high_final** - Final check for high TCP SYN-ACK retries.
48. **tcp_fin_timeout_high** - Detects high TCP FIN timeout. High timeouts can lead to connection exhaustion.
49. **tcp_fin_timeout_high_all** - Checks for high FIN timeout on all interfaces.
50. **tcp_fin_timeout_high_final** - Final check for high TCP FIN timeout.
51. **tcp_keepalive_time_low** - Identifies low TCP keepalive time. Low keepalive can detect dead connections faster.
52. **tcp_keepalive_time_low_final** - Final check for low TCP keepalive time.
53. **tcp_keepalive_probes_low** - Detects low TCP keepalive probes.
54. **tcp_keepalive_probes_low_final** - Final check for low TCP keepalive probes.
55. **tcp_keepalive_intvl_low** - Identifies low TCP keepalive interval.
56. **tcp_keepalive_intvl_low_final** - Final check for low TCP keepalive interval.
57. **tcp_max_syn_backlog_low** - Detects low TCP max SYN backlog. Low backlog can lead to connection drops.
58. **tcp_max_syn_backlog_low_all** - Checks for low SYN backlog on all interfaces.
59. **tcp_max_syn_backlog_low_final** - Final check for low TCP max SYN backlog.
60. **tcp_max_tw_buckets_high** - Identifies high TCP max TIME_WAIT buckets.
61. **tcp_max_tw_buckets_high_final** - Final check for high TCP max TIME_WAIT buckets.
62. **tcp_max_orphans_high** - Detects high TCP max orphan connections.
63. **tcp_max_orphans_high_final** - Final check for high TCP max orphan connections.

#### TCP Retry & Recovery (8 rules)
64. **tcp_retries1_high** - Identifies high TCP retries1 value.
65. **tcp_retries2_high** - Detects high TCP retries2 value. High retries can cause long connection timeouts.
66. **tcp_retries2_high_final** - Final check for high TCP retries2.
67. **tcp_orphan_retries_high** - Identifies high TCP orphan retries.
68. **tcp_orphan_retries_high_final** - Final check for high TCP orphan retries.
69. **tcp_recovery_enabled** - Detects enabled TCP recovery mechanisms.
70. **tcp_recovery_enabled_all** - Checks for enabled TCP recovery on all interfaces.
71. **tcp_recovery_enabled_final** - Final check for enabled TCP recovery.

#### TCP Buffer & Memory (10 rules)
72. **tcp_rmem_max_low** - Detects low TCP receive memory maximum.
73. **tcp_wmem_max_low** - Identifies low TCP send memory maximum.
74. **tcp_mem_low** - Checks for low TCP memory limits.
75. **tcp_adv_win_scale_wrong** - Detects incorrect TCP advanced window scaling.
76. **tcp_app_win_wrong** - Identifies incorrect TCP application window.
77. **tcp_limit_output_bytes_high** - Detects high TCP limit output bytes.
78. **tcp_moderate_rcvbuf_enabled** - Identifies enabled TCP moderate receive buffer.

#### TCP Congestion Control (3 rules)
79. **tcp_congestion_control_wrong** - Detects incorrect TCP congestion control algorithm.
80. **tcp_congestion_control_bbr_missing** - Identifies missing BBR congestion control.
81. **tcp_slow_start_after_idle_enabled** - Detects enabled TCP slow start after idle.
82. **tcp_slow_start_after_idle_enabled_all** - Checks for enabled slow start on all interfaces.
83. **tcp_slow_start_after_idle_enabled_final** - Final check for enabled TCP slow start after idle.

#### TCP Advanced Features (30+ rules)
84. **tcp_tw_reuse_enabled** - Detects enabled TCP TIME_WAIT socket reuse.
85. **tcp_tw_reuse_enabled_final** - Final check for enabled TCP TIME_WAIT reuse.
86. **tcp_tw_recycle_enabled** - Identifies enabled TCP TIME_WAIT socket recycling (deprecated).
87. **tcp_abort_on_overflow_enabled** - Detects enabled TCP abort on overflow.
88. **tcp_abort_on_overflow_enabled_final** - Final check for enabled TCP abort on overflow.
89. **tcp_abort_on_overflow_enabled_final2** - Additional check for TCP abort on overflow.
90. **tcp_no_metrics_save_enabled** - Identifies enabled TCP no metrics save.
91. **tcp_autocorking_enabled** - Detects enabled TCP autocorking.
92. **tcp_early_retrans_enabled** - Identifies enabled TCP early retransmission.
93. **tcp_early_demux_enabled** - Detects enabled TCP early demultiplexing.
94. **tcp_early_demux_enabled_ipv6** - Checks for enabled TCP early demux on IPv6.
95. **tcp_fastopen_enabled** - Identifies enabled TCP Fast Open.
96. **tcp_fastopen_key_missing** - Detects missing TCP Fast Open key.
97. **tcp_fastopen_blackhole_timeout_sec_high** - Identifies high TCP Fast Open blackhole timeout.
98. **tcp_stdurg_enabled** - Detects enabled TCP urgent pointer interpretation.
99. **tcp_rfc1337_enabled** - Identifies enabled TCP RFC 1337 compliance.
100. **tcp_pmtu_enable_disco_enabled** - Detects enabled TCP PMTU discovery.
101. **tcp_mtu_probing_enabled** - Identifies enabled TCP MTU probing.
102. **tcp_mtu_probe_floor_low** - Detects low TCP MTU probe floor.
103. **tcp_mtu_probe_interval_high** - Identifies high TCP MTU probe interval.
104. **tcp_pmtu_probe_floor_low** - Checks for low TCP PMTU probe floor.
105. **tcp_base_mss_low** - Detects low TCP base MSS.
106. **tcp_probe_interval_high** - Identifies high TCP probe interval.
107. **tcp_probe_threshold_high** - Detects high TCP probe threshold.
108. **tcp_min_rtt_wlen_high** - Identifies high TCP minimum RTT window length.
109. **tcp_challenge_ack_limit_high** - Detects high TCP challenge ACK limit.
110. **tcp_comp_sack_nr_high** - Identifies high TCP compressed SACK number.
111. **tcp_comp_sack_slack_high** - Detects high TCP compressed SACK slack.
112. **tcp_comp_sack_delay_ns_high** - Identifies high TCP compressed SACK delay.
113. **tcp_sack_comp_min_high** - Detects high TCP SACK compression minimum.
114. **tcp_sack_comp_max_high** - Identifies high TCP SACK compression maximum.
115. **tcp_backlog_ack_defer_enabled** - Detects enabled TCP backlog ACK deferral.
116. **tcp_backlog_ack_defer_max_high** - Identifies high TCP backlog ACK defer max.
117. **tcp_min_tso_segs_high** - Detects high TCP minimum TSO segments.
118. **tcp_tso_win_divisor_wrong** - Identifies incorrect TCP TSO window divisor.
119. **tcp_pacing_ss_ratio_wrong** - Detects incorrect TCP pacing slow start ratio.
120. **tcp_pacing_ca_ratio_wrong** - Identifies incorrect TCP pacing congestion avoidance ratio.
121. **tcp_default_init_rwnd_low** - Detects low TCP default initial receive window.
122. **tcp_thin_linear_timeouts_high** - Identifies high TCP thin linear timeouts.
123. **tcp_thin_dupack_high** - Detects high TCP thin duplicate ACK threshold.

### UDP Configuration (2 rules)
124. **udp_early_demux_enabled** - Detects enabled UDP early demultiplexing.
125. **udp_early_demux_enabled_ipv6** - Checks for enabled UDP early demux on IPv6.

### Network Queue & Backlog (2 rules)
126. **somaxconn_low** - Detects low socket maximum connections. Low limits can cause connection drops.
127. **netdev_max_backlog_low** - Identifies low network device maximum backlog. Low backlog can cause packet drops.

### IP Configuration (2 rules)
128. **shared_media_disabled** - Detects disabled shared media support.
129. **bootp_relay_disabled** - Identifies disabled BOOTP relay.
130. **accept_source_route_enabled** - Detects enabled source route acceptance. This can be used for network attacks.
131. **icmp_ratemask_wrong** - Identifies incorrect ICMP rate mask.

---

## Severity Levels

Rules are assigned severity levels from 1-5, where:
- **Severity 1**: Critical - Immediate security risk requiring urgent attention
- **Severity 2**: High - Significant security risk requiring prompt remediation
- **Severity 3**: Medium - Moderate security risk that should be addressed
- **Severity 4**: Low - Minor security concern
- **Severity 5**: Informational - Best practice recommendation

---

## Rule Categories by Tag

### Kubernetes (k8s)
All pod rules are tagged with "k8s" indicating they apply to Kubernetes environments.

### Posture
Rules tagged with "posture" relate to security posture and compliance.

### Network
Rules related to network configuration, protocols, and security.

### Security Context
Rules related to container and pod security contexts.

### Capabilities
Rules related to Linux capabilities assigned to containers.

### Volume
Rules related to volume mounts and storage.

### Host
Rules related to host-level security configurations.

---

## Notes for Product Guide

1. **Rule Coverage**: The system provides comprehensive coverage of Kubernetes pod security and host-level security configurations.

2. **Customization**: Rules can be customized based on organizational security policies and compliance requirements.

3. **Severity Mapping**: Severity levels help prioritize remediation efforts based on risk assessment.

4. **Tagging System**: Tags enable filtering and grouping of rules for specific security domains.

5. **Continuous Updates**: Rules are regularly updated to address emerging security threats and best practices.

---

