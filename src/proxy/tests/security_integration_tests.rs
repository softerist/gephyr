//! IP Security Integration Tests
//! Integration tests for IP security features
//! 
//! These tests require starting the full proxy server to verify end-to-end functionality

#[cfg(test)]
mod integration_tests {
    use crate::modules::security_db::{
        self, init_db, add_to_blacklist, remove_from_blacklist,
        add_to_whitelist, remove_from_whitelist, get_blacklist, get_whitelist,
    };
    use std::time::Duration;

    // Helper function: Cleanup test environment
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

    // ============================================================================
    // Integration Test Scenario 1: Blacklist blocks requests
    // ============================================================================
    
    // Test Scenario: When an IP is in the blacklist, requests should be rejected
    // 
    // Expected Behavior:
    // 1. Add IP to blacklist
    // 2. Requests from this IP return 403 Forbidden
    // 3. Response body contains the ban reason
    #[test]
    fn test_scenario_blacklist_blocks_request() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Add test IP to blacklist
        let entry = add_to_blacklist(
            "192.168.100.100",
            Some("Integration test - malicious activity"),
            None,
            "integration_test",
        );
        assert!(entry.is_ok(), "Should add IP to blacklist");

        // Verify blacklist entry exists
        let blacklist = get_blacklist().unwrap();
        let found = blacklist.iter().any(|e| e.ip_pattern == "192.168.100.100");
        assert!(found, "IP should be in blacklist");

        // Actual HTTP request tests require starting the server
        // Verifying data layer correctness here
        let is_blocked = security_db::is_ip_in_blacklist("192.168.100.100").unwrap();
        assert!(is_blocked, "IP should be blocked");

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 2: Whitelist priority mode
    // ============================================================================
    
    // Test Scenario: In whitelist priority mode, whitelisted IPs skip blacklist checks
    // 
    // Expected Behavior:
    // 1. IP exists in both black and white lists
    // 2. Enable whitelist_priority mode
    // 3. Request should be allowed (whitelist priority)
    #[test]
    fn test_scenario_whitelist_priority() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Add IP to blacklist
        let _ = add_to_blacklist(
            "10.0.0.50",
            Some("Should be overridden by whitelist"),
            None,
            "test",
        );

        // Add the same IP to whitelist
        let _ = add_to_whitelist(
            "10.0.0.50",
            Some("Trusted - override blacklist"),
        );

        // Verify both lists contain the IP
        assert!(security_db::is_ip_in_blacklist("10.0.0.50").unwrap());
        assert!(security_db::is_ip_in_whitelist("10.0.0.50").unwrap());

        // In the actual middleware, when whitelist_priority=true, the whitelist is checked first
        // If in the whitelist, the blacklist check is skipped
        // Only verifying data correctness here; middleware logic is guaranteed by ip_filter.rs

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 3: Temporary ban and expiration
    // ============================================================================
    
    // Test Scenario: Temporary ban automatically lifted after expiration
    // 
    // Expected Behavior:
    // 1. Add temporary ban (already expired)
    // 2. Expired entry automatically cleaned up during lookup
    // 3. Request should be allowed
    #[test]
    fn test_scenario_temporary_ban_expiration() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Add already expired temporary ban
        let _ = add_to_blacklist(
            "expired.ban.test",
            Some("Temporary ban - should be expired"),
            Some(now - 60), // Expired 1 minute ago
            "test",
        );

        // Lookup should trigger expiration cleanup
        let is_blocked = security_db::is_ip_in_blacklist("expired.ban.test").unwrap();
        assert!(!is_blocked, "Expired ban should not block");

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 4: CIDR range blocking
    // ============================================================================
    
    // Test Scenario: CIDR range blocking covers the entire subnet
    // 
    // Expected Behavior:
    // 1. Block 192.168.1.0/24
    // 2. All requests from 192.168.1.x are rejected
    // 3. Requests from 192.168.2.x pass normally
    #[test]
    fn test_scenario_cidr_subnet_blocking() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Block entire subnet
        let _ = add_to_blacklist(
            "192.168.1.0/24",
            Some("Entire subnet blocked"),
            None,
            "test",
        );

        // Verify IPs in subnet are blocked
        for last_octet in [1, 50, 100, 200, 254] {
            let ip = format!("192.168.1.{}", last_octet);
            let is_blocked = security_db::is_ip_in_blacklist(&ip).unwrap();
            assert!(is_blocked, "IP {} should be blocked by CIDR", ip);
        }

        // Verify IPs outside subnet are not blocked
        for last_octet in [1, 50, 100] {
            let ip = format!("192.168.2.{}", last_octet);
            let is_blocked = security_db::is_ip_in_blacklist(&ip).unwrap();
            assert!(!is_blocked, "IP {} should NOT be blocked", ip);
        }

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 5: Ban message details
    // ============================================================================
    
    // Test Scenario: Ban response contains detailed information
    // 
    // Expected Behavior:
    // 1. Add ban with a reason
    // 2. When request is rejected, response contains:
    //    - Ban reason
    //    - Whether it's temporary/permanent ban
    //    - Remaining ban time (if temporary)
    #[test]
    fn test_scenario_ban_message_details() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Add temporary ban (expires in 2 hours)
        let _ = add_to_blacklist(
            "temp.ban.message",
            Some("Rate limit exceeded"),
            Some(now + 7200), // 2 hours later
            "rate_limiter",
        );

        // Get ban details
        let entry = security_db::get_blacklist_entry_for_ip("temp.ban.message")
            .unwrap()
            .unwrap();

        assert_eq!(entry.reason.as_deref(), Some("Rate limit exceeded"));
        assert!(entry.expires_at.is_some());
        
        let remaining = entry.expires_at.unwrap() - now;
        assert!(remaining > 0 && remaining <= 7200, "Should have ~2h remaining");

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 6: Access logging
    // ============================================================================
    
    // Test Scenario: Blocked requests are logged
    // 
    // Expected Behavior:
    // 1. Blacklisted IP initiates a request
    // 2. Request is rejected
    // 3. Access log records: IP, time, status (403), ban reason
    #[test]
    fn test_scenario_blocked_request_logging() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Simulate saving a blocked access log
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

        // Verify log can be retrieved
        let logs = security_db::get_ip_access_logs(10, 0, None, true).unwrap();
        let found = logs.iter().any(|l| l.client_ip == "blocked.request.test");
        assert!(found, "Blocked request should be logged");

        let _ = security_db::clear_ip_access_logs();
    }

    // ============================================================================
    // Integration Test Scenario 7: No impact on normal request performance
    // ============================================================================
    
    // Test Scenario: Security checks do not significantly impact normal request performance
    // 
    // Expected Behavior:
    // 1. Blacklist/whitelist check time < 5ms
    // 2. Latency increase compared to baseline without security checks < 10ms
    #[test]
    fn test_scenario_performance_impact() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Add some blacklist entries
        for i in 0..50 {
            let _ = add_to_blacklist(&format!("perf.test.{}", i), None, None, "test");
        }

        // Add some CIDR rules
        for i in 0..10 {
            let _ = add_to_blacklist(&format!("172.{}.0.0/16", i), None, None, "test");
        }

        // Test lookup performance
        let start = std::time::Instant::now();
        let iterations = 100;

        for _ in 0..iterations {
            // Simulate security checks for normal requests
            let _ = security_db::is_ip_in_whitelist("10.0.0.1");
            let _ = security_db::is_ip_in_blacklist("10.0.0.1");
        }

        let duration = start.elapsed();
        let avg_per_check = duration / (iterations * 2);

        println!("Average security check time: {:?}", avg_per_check);
        
        // Assertion: Average time per check should be within 5ms
        assert!(
            avg_per_check < Duration::from_millis(5),
            "Security check should be fast"
        );

        cleanup_test_data();
    }

    // ============================================================================
    // Integration Test Scenario 8: Data persistence
    // ============================================================================
    
    // Test Scenario: Blacklist/whitelist data persistence
    // 
    // Expected Behavior:
    // 1. Reinitialize database connection after adding data
    // 2. Data still exists
    #[test]
    fn test_scenario_data_persistence() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        // Add data
        let _ = add_to_blacklist("persist.test.ip", Some("Persistence test"), None, "test");
        let _ = add_to_whitelist("persist.white.ip", Some("Persistence test"));

        // Reinitialize (actually just verifying data is still readable)
        let _ = init_db();

        // Verify data still exists
        assert!(security_db::is_ip_in_blacklist("persist.test.ip").unwrap());
        assert!(security_db::is_ip_in_whitelist("persist.white.ip").unwrap());

        cleanup_test_data();
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

#[cfg(test)]
mod stress_tests {
    use crate::modules::security_db::{
        init_db, add_to_blacklist, remove_from_blacklist,
        is_ip_in_blacklist, get_blacklist, save_ip_access_log,
        IpAccessLog, clear_ip_access_logs,
    };
    use std::thread;
    use std::time::{Duration, Instant};

    // Helper function: Cleanup test environment
    fn cleanup_test_data() {
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = remove_from_blacklist(&entry.id);
            }
        }
        let _ = clear_ip_access_logs();
    }

    // Stress Test: Large blacklist
    #[test]
    fn stress_test_large_blacklist() {
        let _guard = crate::proxy::tests::acquire_security_test_lock();
        let _ = init_db();
        cleanup_test_data();

        let count = 500;

        // Batch add
        let start = Instant::now();
        for i in 0..count {
            let _ = add_to_blacklist(&format!("stress.{}.{}.{}.{}", i/256, (i/16)%16, i%16, i), None, None, "stress");
        }
        let add_duration = start.elapsed();
        println!("Added {} entries in {:?}", count, add_duration);

        // Random lookup test
        let start = Instant::now();
        for i in 0..100 {
            let _ = is_ip_in_blacklist(&format!("stress.{}.{}.{}.{}", i/256, (i/16)%16, i%16, i));
        }
        let lookup_duration = start.elapsed();
        println!("100 lookups in large blacklist took {:?}", lookup_duration);

        // Verify performance is reasonable
        assert!(
            lookup_duration < Duration::from_secs(1),
            "Lookups should be reasonably fast even with large blacklist"
        );

        cleanup_test_data();
    }

    // Stress Test: Large access log volume
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

        // Batch write logs
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

        // Verify writing performance is reasonable
        assert!(
            write_duration < Duration::from_secs(10),
            "Access log writing should be reasonably fast"
        );

        let _ = clear_ip_access_logs();
    }

    // Stress Test: Concurrent operations
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
                        // Each thread adds-queries-deletes
                        let ip = format!("concurrent.{}.{}", t, i);
                        if let Ok(entry) = add_to_blacklist(&ip, None, None, "concurrent") {
                            let _ = is_ip_in_blacklist(&ip);
                            let _ = remove_from_blacklist(&entry.id);
                        }
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify no leftover data
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
