#[cfg(test)]
mod integration_tests {
    use crate::modules::persistence::security_db::{
        self, add_to_blacklist, add_to_whitelist, get_blacklist, get_whitelist, init_db,
        remove_from_blacklist, remove_from_whitelist,
    };
    use std::time::Duration;
    fn cleanup_test_data() {
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = remove_from_blacklist(&entry.id);
            }
        }
        if let Ok(entries) = get_whitelist() {
            for entry in entries {
                let _ = remove_from_whitelist(&entry.id);
            }
        }
    }
    #[test]
    fn test_scenario_blacklist_blocks_request() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let entry = add_to_blacklist(
            "192.168.100.100",
            Some("Integration test - malicious activity"),
            None,
            "integration_test",
        );
        assert!(entry.is_ok(), "Should add IP to blacklist");
        let blacklist = get_blacklist().unwrap();
        let found = blacklist.iter().any(|e| e.ip_pattern == "192.168.100.100");
        assert!(found, "IP should be in blacklist");
        let is_blocked = security_db::is_ip_in_blacklist("192.168.100.100").unwrap();
        assert!(is_blocked, "IP should be blocked");

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_whitelist_priority() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let _ = add_to_blacklist(
            "10.0.0.50",
            Some("Should be overridden by whitelist"),
            None,
            "test",
        );
        let _ = add_to_whitelist("10.0.0.50", Some("Trusted - override blacklist"));
        assert!(security_db::is_ip_in_blacklist("10.0.0.50").unwrap());
        assert!(security_db::is_ip_in_whitelist("10.0.0.50").unwrap());

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_temporary_ban_expiration() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let _ = add_to_blacklist(
            "expired.ban.test",
            Some("Temporary ban - should be expired"),
            Some(now - 60),
            "test",
        );
        let is_blocked = security_db::is_ip_in_blacklist("expired.ban.test").unwrap();
        assert!(!is_blocked, "Expired ban should not block");

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_cidr_subnet_blocking() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let _ = add_to_blacklist(
            "192.168.1.0/24",
            Some("Entire subnet blocked"),
            None,
            "test",
        );
        for last_octet in [1, 50, 100, 200, 254] {
            let ip = format!("192.168.1.{}", last_octet);
            let is_blocked = security_db::is_ip_in_blacklist(&ip).unwrap();
            assert!(is_blocked, "IP {} should be blocked by CIDR", ip);
        }
        for last_octet in [1, 50, 100] {
            let ip = format!("192.168.2.{}", last_octet);
            let is_blocked = security_db::is_ip_in_blacklist(&ip).unwrap();
            assert!(!is_blocked, "IP {} should NOT be blocked", ip);
        }

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_ban_message_details() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let _ = add_to_blacklist(
            "temp.ban.message",
            Some("Rate limit exceeded"),
            Some(now + 7200),
            "rate_limiter",
        );
        let entry = security_db::get_blacklist_entry_for_ip("temp.ban.message")
            .unwrap()
            .unwrap();

        assert_eq!(entry.reason.as_deref(), Some("Rate limit exceeded"));
        assert!(entry.expires_at.is_some());

        let remaining = entry.expires_at.unwrap() - now;
        assert!(
            remaining > 0 && remaining <= 7200,
            "Should have ~2h remaining"
        );

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_blocked_request_logging() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let log = security_db::IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "blocked.request.test".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            method: Some("POST".to_string()),
            path: Some("/v1/messages".to_string()),
            user_agent: Some("TestClient/1.0".to_string()),
            status: Some(403),
            duration: Some(0),
            api_key_hash: None,
            blocked: true,
            block_reason: Some("IP in blacklist".to_string()),
            username: None,
        };

        let save_result = security_db::save_ip_access_log(&log);
        assert!(save_result.is_ok());
        let logs = security_db::get_ip_access_logs(10, 0, None, true).unwrap();
        let found = logs.iter().any(|l| l.client_ip == "blocked.request.test");
        assert!(found, "Blocked request should be logged");

        let _ = security_db::clear_ip_access_logs();
    }
    #[test]
    fn test_scenario_performance_impact() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        for i in 0..50 {
            let _ = add_to_blacklist(&format!("perf.test.{}", i), None, None, "test");
        }
        for i in 0..10 {
            let _ = add_to_blacklist(&format!("172.{}.0.0/16", i), None, None, "test");
        }
        let start = std::time::Instant::now();
        let iterations = 100;

        for _ in 0..iterations {
            let _ = security_db::is_ip_in_whitelist("10.0.0.1");
            let _ = security_db::is_ip_in_blacklist("10.0.0.1");
        }

        let duration = start.elapsed();
        let avg_per_check = duration / (iterations * 2);

        println!("Average security check time: {:?}", avg_per_check);
        assert!(
            avg_per_check < Duration::from_millis(5),
            "Security check should be fast"
        );

        cleanup_test_data();
    }
    #[test]
    fn test_scenario_data_persistence() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();
        let _ = add_to_blacklist("persist.test.ip", Some("Persistence test"), None, "test");
        let _ = add_to_whitelist("persist.white.ip", Some("Persistence test"));
        let _ = init_db();
        assert!(security_db::is_ip_in_blacklist("persist.test.ip").unwrap());
        assert!(security_db::is_ip_in_whitelist("persist.white.ip").unwrap());

        cleanup_test_data();
    }
}

#[cfg(test)]
mod stress_tests {
    use crate::modules::persistence::security_db::{
        add_to_blacklist, clear_ip_access_logs, get_blacklist, init_db, is_ip_in_blacklist,
        remove_from_blacklist, save_ip_access_log, IpAccessLog,
    };
    use std::thread;
    use std::time::{Duration, Instant};
    fn cleanup_test_data() {
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = remove_from_blacklist(&entry.id);
            }
        }
        let _ = clear_ip_access_logs();
    }
    #[test]
    fn stress_test_large_blacklist() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        let count = 500;
        let start = Instant::now();
        for i in 0..count {
            let _ = add_to_blacklist(
                &format!("stress.{}.{}.{}.{}", i / 256, (i / 16) % 16, i % 16, i),
                None,
                None,
                "stress",
            );
        }
        let add_duration = start.elapsed();
        println!("Added {} entries in {:?}", count, add_duration);
        let start = Instant::now();
        for i in 0..100 {
            let _ = is_ip_in_blacklist(&format!(
                "stress.{}.{}.{}.{}",
                i / 256,
                (i / 16) % 16,
                i % 16,
                i
            ));
        }
        let lookup_duration = start.elapsed();
        println!("100 lookups in large blacklist took {:?}", lookup_duration);
        assert!(
            lookup_duration < Duration::from_secs(1),
            "Lookups should be reasonably fast even with large blacklist"
        );

        cleanup_test_data();
    }
    #[test]
    fn stress_test_access_logging() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        let _ = clear_ip_access_logs();

        let count = 1000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let start = Instant::now();
        for i in 0..count {
            let log = IpAccessLog {
                id: uuid::Uuid::new_v4().to_string(),
                client_ip: format!("log.stress.{}", i % 100),
                timestamp: now,
                method: Some("POST".to_string()),
                path: Some("/v1/messages".to_string()),
                user_agent: Some("StressTest/1.0".to_string()),
                status: Some(200),
                duration: Some(100),
                api_key_hash: Some("hash".to_string()),
                blocked: false,
                block_reason: None,
                username: None,
            };
            let _ = save_ip_access_log(&log);
        }
        let write_duration = start.elapsed();
        println!("Wrote {} access logs in {:?}", count, write_duration);
        assert!(
            write_duration < Duration::from_secs(10),
            "Access log writing should be reasonably fast"
        );

        let _ = clear_ip_access_logs();
    }
    #[test]
    fn stress_test_concurrent_operations() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        let thread_count = 5;
        let ops_per_thread = 20;

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                thread::spawn(move || {
                    for i in 0..ops_per_thread {
                        let ip = format!("concurrent.{}.{}", t, i);
                        if let Ok(entry) = add_to_blacklist(&ip, None, None, "concurrent") {
                            let _ = is_ip_in_blacklist(&ip);
                            let _ = remove_from_blacklist(&entry.id);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }
        let remaining = get_blacklist().unwrap();
        let concurrent_remaining: Vec<_> = remaining
            .iter()
            .filter(|e| e.ip_pattern.starts_with("concurrent."))
            .collect();

        assert!(
            concurrent_remaining.is_empty(),
            "All concurrent test data should be cleaned up"
        );

        cleanup_test_data();
    }
}
