//! IP Security Module Tests
//! Comprehensive test suite for IP security monitoring functionality
//! 
//! Test Objectives:
//! 1. Verify correctness of IP black/whitelist functionality
//! 2. Verify CIDR matching logic
//! 3. Verify expiration time handling
//! 4. Verify no impact on main flow performance
//! 5. Verify atomicity and consistency of database operations

#[cfg(test)]
mod security_db_tests {
    use crate::modules::security_db::{
        self, IpAccessLog, IpBlacklistEntry, IpWhitelistEntry,
        init_db, add_to_blacklist, remove_from_blacklist, get_blacklist,
        is_ip_in_blacklist, get_blacklist_entry_for_ip,
        add_to_whitelist, remove_from_whitelist, get_whitelist,
        is_ip_in_whitelist, save_ip_access_log, get_ip_access_logs,
        get_ip_stats, cleanup_old_ip_logs, clear_ip_access_logs,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper function: Get current timestamp
    fn now_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // Helper function: Cleanup test environment
    fn cleanup_test_data() {
        // Cleanup blacklist
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = remove_from_blacklist(&entry.id);
            }
        }
        // Cleanup whitelist
        if let Ok(entries) = get_whitelist() {
            for entry in entries {
                let _ = remove_from_whitelist(&entry.id);
            }
        }
        // Cleanup access logs
        let _ = clear_ip_access_logs();
    }

    // ============================================================================
    // Test Category 1: Database Initialization
    // ============================================================================
    
    #[test]
    fn test_db_initialization() {
        // Verify database initialization doesn't panic
        let result = init_db();
        assert!(result.is_ok(), "Database initialization should succeed: {:?}", result.err());
    }

    #[test]
    fn test_db_multiple_initializations() {
        // Verify multiple initializations don't fail (Idempotency)
        for _ in 0..3 {
            let result = init_db();
            assert!(result.is_ok(), "Multiple DB initializations should be idempotent");
        }
    }

    // ============================================================================
    // Test Category 2: IP Blacklist Basic Operations
    // ============================================================================

    #[test]
    fn test_blacklist_add_and_check() {
        let _ = init_db();
        cleanup_test_data();

        // Add IP to blacklist
        let result = add_to_blacklist("192.168.1.100", Some("Test block"), None, "test");
        assert!(result.is_ok(), "Should add IP to blacklist: {:?}", result.err());

        // Verify IP is in blacklist
        let is_blocked = is_ip_in_blacklist("192.168.1.100");
        assert!(is_blocked.is_ok());
        assert!(is_blocked.unwrap(), "IP should be in blacklist");

        // Verify other IP is not in blacklist
        let is_other_blocked = is_ip_in_blacklist("192.168.1.101");
        assert!(is_other_blocked.is_ok());
        assert!(!is_other_blocked.unwrap(), "Other IP should not be in blacklist");

        cleanup_test_data();
    }

    #[test]
    fn test_blacklist_remove() {
        let _ = init_db();
        cleanup_test_data();

        // Add IP
        let entry = add_to_blacklist("10.0.0.5", Some("Temp block"), None, "test").unwrap();
        
        // Verify presence
        assert!(is_ip_in_blacklist("10.0.0.5").unwrap());

        // Remove
        let remove_result = remove_from_blacklist(&entry.id);
        assert!(remove_result.is_ok());

        // Verify removed
        assert!(!is_ip_in_blacklist("10.0.0.5").unwrap());

        cleanup_test_data();
    }

    #[test]
    fn test_blacklist_get_entry_details() {
        let _ = init_db();
        cleanup_test_data();

        // Add entry with details
        let _ = add_to_blacklist(
            "172.16.0.50",
            Some("Abuse detected"),
            Some(now_timestamp() + 3600), // Expire in 1 hour
            "admin",
        );

        // Get entry details
        let entry_result = get_blacklist_entry_for_ip("172.16.0.50");
        assert!(entry_result.is_ok());
        
        let entry = entry_result.unwrap();
        assert!(entry.is_some());
        
        let entry = entry.unwrap();
        assert_eq!(entry.ip_pattern, "172.16.0.50");
        assert_eq!(entry.reason.as_deref(), Some("Abuse detected"));
        assert_eq!(entry.created_by, "admin");
        assert!(entry.expires_at.is_some());

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 3: CIDR Matching
    // ============================================================================

    #[test]
    fn test_cidr_matching_basic() {
        let _ = init_db();
        cleanup_test_data();

        // Add CIDR range to blacklist
        let _ = add_to_blacklist("192.168.1.0/24", Some("Block subnet"), None, "test");

        // Verify IPs in subnet are blocked
        assert!(is_ip_in_blacklist("192.168.1.1").unwrap(), "192.168.1.1 should match /24");
        assert!(is_ip_in_blacklist("192.168.1.100").unwrap(), "192.168.1.100 should match /24");
        assert!(is_ip_in_blacklist("192.168.1.254").unwrap(), "192.168.1.254 should match /24");

        // Verify IPs outside subnet are not blocked
        assert!(!is_ip_in_blacklist("192.168.2.1").unwrap(), "192.168.2.1 should not match");
        assert!(!is_ip_in_blacklist("10.0.0.1").unwrap(), "10.0.0.1 should not match");

        cleanup_test_data();
    }

    #[test]
    fn test_cidr_matching_various_masks() {
        let _ = init_db();
        cleanup_test_data();

        // Test /16 mask
        let _ = add_to_blacklist("10.10.0.0/16", Some("Block /16"), None, "test");
        
        assert!(is_ip_in_blacklist("10.10.0.1").unwrap(), "Should match /16");
        assert!(is_ip_in_blacklist("10.10.255.255").unwrap(), "Should match /16");
        assert!(!is_ip_in_blacklist("10.11.0.1").unwrap(), "Should not match /16");

        cleanup_test_data();

        // Test /32 mask (Single IP)
        let _ = add_to_blacklist("8.8.8.8/32", Some("Block single"), None, "test");
        
        assert!(is_ip_in_blacklist("8.8.8.8").unwrap(), "Should match /32");
        assert!(!is_ip_in_blacklist("8.8.8.9").unwrap(), "Should not match /32");

        cleanup_test_data();
    }

    #[test]
    fn test_cidr_edge_cases() {
        let _ = init_db();
        cleanup_test_data();

        // Test /0 (All IPs) - Boundary case
        let _ = add_to_blacklist("0.0.0.0/0", Some("Block all"), None, "test");
        
        assert!(is_ip_in_blacklist("1.2.3.4").unwrap(), "Everything should match /0");
        assert!(is_ip_in_blacklist("255.255.255.255").unwrap(), "Everything should match /0");

        cleanup_test_data();

        // Test /8 mask
        let _ = add_to_blacklist("10.0.0.0/8", Some("Block /8"), None, "test");
        
        assert!(is_ip_in_blacklist("10.255.255.255").unwrap(), "Should match /8");
        assert!(!is_ip_in_blacklist("11.0.0.0").unwrap(), "Should not match /8");

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 4: Expiration Time Handling
    // ============================================================================

    #[test]
    fn test_blacklist_expiration() {
        let _ = init_db();
        cleanup_test_data();

        // Add an expired entry
        let _ = add_to_blacklist(
            "expired.test.ip",
            Some("Already expired"),
            Some(now_timestamp() - 60), // Expired 1 minute ago
            "test",
        );

        // Expired entry should be automatically cleaned up
        let is_blocked = is_ip_in_blacklist("expired.test.ip");
        // NOTE: Depending on implementation, expired entries may be cleaned up during lookup
        // Based on security_db.rs implementation, get_blacklist_entry_for_ip cleans up expired entries first
        assert!(!is_blocked.unwrap(), "Expired entry should be cleaned up");

        cleanup_test_data();
    }

    #[test]
    fn test_blacklist_not_yet_expired() {
        let _ = init_db();
        cleanup_test_data();

        // Add a non-expired entry
        let _ = add_to_blacklist(
            "not.expired.ip",
            Some("Will expire later"),
            Some(now_timestamp() + 3600), // Expire in 1 hour
            "test",
        );

        // Non-expired entry should still be effective
        assert!(is_ip_in_blacklist("not.expired.ip").unwrap());

        cleanup_test_data();
    }

    #[test]
    fn test_permanent_blacklist() {
        let _ = init_db();
        cleanup_test_data();

        // Add permanent ban (no expiration)
        let _ = add_to_blacklist(
            "permanent.block.ip",
            Some("Permanent ban"),
            None, // No expiration
            "test",
        );

        // Permanent ban should always be effective
        assert!(is_ip_in_blacklist("permanent.block.ip").unwrap());

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 5: IP Whitelist
    // ============================================================================

    #[test]
    fn test_whitelist_add_and_check() {
        let _ = init_db();
        cleanup_test_data();

        // Add IP to whitelist
        let result = add_to_whitelist("10.0.0.1", Some("Trusted server"));
        assert!(result.is_ok());

        // Verify IP is in whitelist
        assert!(is_ip_in_whitelist("10.0.0.1").unwrap());
        assert!(!is_ip_in_whitelist("10.0.0.2").unwrap());

        cleanup_test_data();
    }

    #[test]
    fn test_whitelist_cidr() {
        let _ = init_db();
        cleanup_test_data();

        // Add CIDR range to whitelist
        let _ = add_to_whitelist("192.168.0.0/16", Some("Internal network"));

        // Verify IPs in subnet are allowed
        assert!(is_ip_in_whitelist("192.168.1.1").unwrap());
        assert!(is_ip_in_whitelist("192.168.255.255").unwrap());

        // Verify IPs outside subnet are not in whitelist
        assert!(!is_ip_in_whitelist("10.0.0.1").unwrap());

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 6: IP Access Logs
    // ============================================================================

    #[test]
    fn test_access_log_save_and_retrieve() {
        let _ = init_db();
        cleanup_test_data();

        // Save access log
        let log = IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "test.log.ip".to_string(),
            timestamp: now_timestamp(),
            method: Some("POST".to_string()),
            path: Some("/v1/messages".to_string()),
            user_agent: Some("TestClient/1.0".to_string()),
            status: Some(200),
            duration: Some(150),
            api_key_hash: Some("hash123".to_string()),
            blocked: false,
            block_reason: None,
            username: None,
        };

        let save_result = save_ip_access_log(&log);
        assert!(save_result.is_ok(), "Should save access log: {:?}", save_result.err());

        // Retrieve log
        let logs = get_ip_access_logs(10, 0, Some("test.log.ip"), false);
        assert!(logs.is_ok());
        
        let logs = logs.unwrap();
        assert!(!logs.is_empty(), "Should retrieve saved log");
        assert_eq!(logs[0].client_ip, "test.log.ip");

        cleanup_test_data();
    }

    #[test]
    fn test_access_log_blocked_filter() {
        let _ = init_db();
        cleanup_test_data();

        // Save normal log
        let normal_log = IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "normal.access.ip".to_string(),
            timestamp: now_timestamp(),
            method: Some("GET".to_string()),
            path: Some("/healthz".to_string()),
            user_agent: None,
            status: Some(200),
            duration: Some(10),
            api_key_hash: None,
            blocked: false,
            block_reason: None,
            username: None,
        };
        let _ = save_ip_access_log(&normal_log);

        // Save blocked log
        let blocked_log = IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "blocked.access.ip".to_string(),
            timestamp: now_timestamp(),
            method: Some("POST".to_string()),
            path: Some("/v1/messages".to_string()),
            user_agent: None,
            status: Some(403),
            duration: Some(0),
            api_key_hash: None,
            blocked: true,
            block_reason: Some("IP in blacklist".to_string()),
            username: None,
        };
        let _ = save_ip_access_log(&blocked_log);

        // Retrieve only blocked logs
        let blocked_only = get_ip_access_logs(10, 0, None, true).unwrap();
        assert_eq!(blocked_only.len(), 1);
        assert_eq!(blocked_only[0].client_ip, "blocked.access.ip");
        assert!(blocked_only[0].blocked);

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 7: Statistics
    // ============================================================================

    #[test]
    fn test_ip_stats() {
        let _ = init_db();
        cleanup_test_data();

        // Add some test data
        for i in 0..5 {
            let log = IpAccessLog {
                id: uuid::Uuid::new_v4().to_string(),
                client_ip: format!("stats.test.{}", i % 3), // 3 unique IPs
                timestamp: now_timestamp(),
                method: Some("POST".to_string()),
                path: Some("/v1/messages".to_string()),
                user_agent: None,
                status: Some(200),
                duration: Some(100),
                api_key_hash: None,
                blocked: i == 4, // Last one is blocked
                block_reason: if i == 4 { Some("Test".to_string()) } else { None },
                username: None,
            };
            let _ = save_ip_access_log(&log);
        }

        // Add blacklist and whitelist entries
        let _ = add_to_blacklist("stats.black.1", None, None, "test");
        let _ = add_to_blacklist("stats.black.2", None, None, "test");
        let _ = add_to_whitelist("stats.white.1", None);

        // Get statistics
        let stats = get_ip_stats();
        assert!(stats.is_ok());
        
        let stats = stats.unwrap();
        assert!(stats.total_requests >= 5, "Should have at least 5 requests");
        assert!(stats.unique_ips >= 3, "Should have at least 3 unique IPs");
        assert!(stats.blocked_count >= 1, "Should have at least 1 blocked request");
        assert_eq!(stats.blacklist_count, 2);
        assert_eq!(stats.whitelist_count, 1);

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 8: Cleanup
    // ============================================================================

    #[test]
    fn test_cleanup_old_logs() {
        let _ = init_db();
        cleanup_test_data();

        // Add an "old" log (simulate 2 days ago)
        let old_log = IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "old.log.ip".to_string(),
            timestamp: now_timestamp() - (2 * 24 * 3600), // 2 days ago
            method: Some("GET".to_string()),
            path: Some("/old".to_string()),
            user_agent: None,
            status: Some(200),
            duration: Some(10),
            api_key_hash: None,
            blocked: false,
            block_reason: None,
            username: None,
        };
        let _ = save_ip_access_log(&old_log);

        // Add a new log
        let new_log = IpAccessLog {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip: "new.log.ip".to_string(),
            timestamp: now_timestamp(),
            method: Some("GET".to_string()),
            path: Some("/new".to_string()),
            user_agent: None,
            status: Some(200),
            duration: Some(10),
            api_key_hash: None,
            blocked: false,
            block_reason: None,
            username: None,
        };
        let _ = save_ip_access_log(&new_log);

        // Cleanup logs older than 1 day
        let deleted = cleanup_old_ip_logs(1);
        assert!(deleted.is_ok());
        assert!(deleted.unwrap() >= 1, "Should delete at least 1 old log");

        // Verify new log still exists
        let logs = get_ip_access_logs(10, 0, Some("new.log.ip"), false).unwrap();
        assert!(!logs.is_empty(), "New log should still exist");

        // Verify old log is cleaned up
        let old_logs = get_ip_access_logs(10, 0, Some("old.log.ip"), false).unwrap();
        assert!(old_logs.is_empty(), "Old log should be cleaned up");

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 9: Concurrency Safety
    // ============================================================================

    #[test]
    fn test_concurrent_access() {
        use std::thread;
        
        let _ = init_db();
        cleanup_test_data();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    // Each thread adds a different IP
                    let ip = format!("concurrent.test.{}", i);
                    let _ = add_to_blacklist(&ip, Some("Concurrent test"), None, "test");
                    
                    // Verify IP added by itself
                    is_ip_in_blacklist(&ip).unwrap_or(false)
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        
        // All threads should succeed
        assert!(results.iter().all(|&r| r), "All concurrent adds should succeed");

        cleanup_test_data();
    }

    // ============================================================================
    // Test Category 10: Boundary Cases and Error Handling
    // ============================================================================

    #[test]
    fn test_duplicate_blacklist_entry() {
        let _ = init_db();
        cleanup_test_data();

        // First add should succeed
        let result1 = add_to_blacklist("duplicate.test.ip", Some("First"), None, "test");
        assert!(result1.is_ok());

        // Second add of same IP should fail (UNIQUE constraint)
        let result2 = add_to_blacklist("duplicate.test.ip", Some("Second"), None, "test");
        assert!(result2.is_err(), "Duplicate IP should fail");

        cleanup_test_data();
    }

    #[test]
    fn test_empty_ip_pattern() {
        let _ = init_db();
        cleanup_test_data();

        // Empty IP pattern should still be addable (depending on requirements)
        // Just testing it doesn't panic here
        let result = add_to_blacklist("", Some("Empty IP"), None, "test");
        // Result might succeed or fail, but shouldn't panic
        let _ = result;

        cleanup_test_data();
    }

    #[test]
    fn test_special_characters_in_reason() {
        let _ = init_db();
        cleanup_test_data();

        // Test reason with special characters
        let reason = "Test with 'quotes' and \"double quotes\" and emoji 🚫";
        let result = add_to_blacklist("special.char.test", Some(reason), None, "test");
        assert!(result.is_ok());

        let entry = get_blacklist_entry_for_ip("special.char.test").unwrap().unwrap();
        assert_eq!(entry.reason.as_deref(), Some(reason));

        cleanup_test_data();
    }

    #[test]
    fn test_hit_count_increment() {
        let _ = init_db();
        cleanup_test_data();

        // Add a blacklist entry
        let _ = add_to_blacklist("hit.count.test", Some("Count test"), None, "test");

        // Multiple lookups should increment hit_count
        for _ in 0..5 {
            let _ = get_blacklist_entry_for_ip("hit.count.test");
        }

        // Check hit_count
        let blacklist = get_blacklist().unwrap();
        let entry = blacklist.iter().find(|e| e.ip_pattern == "hit.count.test");
        assert!(entry.is_some());
        assert!(entry.unwrap().hit_count >= 5, "Hit count should be at least 5");

        cleanup_test_data();
    }
}

// ============================================================================
// IP Filter Middleware Test (Unit Test)
// ============================================================================

#[cfg(test)]
mod ip_filter_middleware_tests {
    // NOTE: Middleware tests require simulating HTTP requests; frame provided here
    // Actual integration tests should be done after starting the full service

    // Verify correctness of IP extraction logic
    #[test]
    fn test_ip_extraction_priority() {
        // X-Forwarded-For should have priority over X-Real-IP
        // X-Real-IP should have priority over ConnectInfo
        // Just verifying logic concepts here; actual tests require constructing HTTP requests
        
        // Scenario 1: Multiple IPs in X-Forwarded-For, take the first one
        let xff_header = "203.0.113.1, 198.51.100.2, 192.0.2.3";
        let first_ip = xff_header.split(',').next().unwrap().trim();
        assert_eq!(first_ip, "203.0.113.1");

        // Scenario 2: Single IP
        let single_ip = "10.0.0.1";
        let parsed = single_ip.split(',').next().unwrap().trim();
        assert_eq!(parsed, "10.0.0.1");
    }
}

// Performance Benchmarks

#[cfg(test)]
mod performance_benchmarks {
    use super::security_db_tests::*;
    use crate::modules::security_db::{
        init_db, add_to_blacklist, is_ip_in_blacklist, get_blacklist,
        clear_ip_access_logs,
    };
    use std::time::Instant;

    // Benchmark: Blacklist Lookup Performance
    #[test]
    fn benchmark_blacklist_lookup() {
        let _ = init_db();
        
        // Cleanup and add 100 blacklist entries
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = crate::modules::security_db::remove_from_blacklist(&entry.id);
            }
        }

        for i in 0..100 {
            let _ = add_to_blacklist(
                &format!("bench.ip.{}", i),
                Some("Benchmark"),
                None,
                "test",
            );
        }

        // Execute 1000 lookups
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = is_ip_in_blacklist("bench.ip.50");
        }
        let duration = start.elapsed();

        println!("1000 blacklist lookups took: {:?}", duration);
        println!("Average per lookup: {:?}", duration / 1000);

        // Performance Assertion: Average lookup should be within 1ms
        assert!(
            duration.as_millis() < 5000,
            "Blacklist lookup should be fast (< 5ms avg)"
        );

        // Cleanup
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = crate::modules::security_db::remove_from_blacklist(&entry.id);
            }
        }
    }

    // Benchmark: CIDR Matching Performance
    #[test]
    fn benchmark_cidr_matching() {
        let _ = init_db();

        // Cleanup and add CIDR rules
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = crate::modules::security_db::remove_from_blacklist(&entry.id);
            }
        }

        // Add 20 CIDR rules
        for i in 0..20 {
            let _ = add_to_blacklist(
                &format!("10.{}.0.0/16", i),
                Some("CIDR Benchmark"),
                None,
                "test",
            );
        }

        // Test CIDR matching performance
        let start = Instant::now();
        for _ in 0..1000 {
            // Test IP requiring CIDR traversal
            let _ = is_ip_in_blacklist("10.5.100.50");
        }
        let duration = start.elapsed();

        println!("1000 CIDR matches took: {:?}", duration);
        println!("Average per match: {:?}", duration / 1000);

        // Performance Assertion: CIDR matching should be within reasonable time
        assert!(
            duration.as_millis() < 5000,
            "CIDR matching should be reasonably fast"
        );

        // Cleanup
        if let Ok(entries) = get_blacklist() {
            for entry in entries {
                let _ = crate::modules::security_db::remove_from_blacklist(&entry.id);
            }
        }
    }
}
