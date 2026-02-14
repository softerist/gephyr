
    #[test]
    fn test_custom_web_search_function_downgrade() {
        let tools = Some(vec![json!({
            "functionDeclarations": [
                { "name": "web_search", "parameters": {} }
            ]
        })]);

        let config = resolve_request_config("gemini-3-pro", "gemini-3-pro", &tools);

        assert_eq!(config.request_type, "web_search");
        assert_eq!(config.final_model, "gemini-3-flash");
        assert!(config.inject_google_search);
    }