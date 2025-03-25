// API Configuration
const config = {
    // AWS Configuration
    aws: {
        accessKeyId: 'AKIA_FAKE_EXAMPLE_KEY_FOR_TESTING',
        secretAccessKey: 'wJalrFAKEKEYFORTESTINGEXAMPLEKEY'
    },

    // GitHub Configuration
    github: {
        token: 'ghp_FAKEGITHUBTOKEN123456789012345'
    },

    // Stripe Configuration
    stripe: {
        liveKey: 'sk_live_FAKESTRIPEKEY123TESTING',
        testKey: 'sk_test_FAKESTRIPEKEY123TESTING'
    },

    // Google Configuration
    google: {
        apiKey: 'AIza_FAKE_GOOGLE_API_KEY_TESTING'
    },

    // Example configurations (should be ignored)
    example: {
        apiKey: 'YOUR_API_KEY_HERE',
        testKey: 'test_key_1234567890'
    }
};

module.exports = config; 