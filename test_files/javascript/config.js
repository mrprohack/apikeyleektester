// API Configuration
const config = {
    // AWS Configuration
    aws: {
        accessKeyId: 'AKIAMOCKAWSKEY0000000000000',
        secretAccessKey: 'MockAwsSecretKey000000000000000000000000'
    },

    // GitHub Configuration
    github: {
        token: 'ghp_m0ckgithubtoken000000000000000'
    },

    // Stripe Configuration
    stripe: {
        liveKey: 'sk_notareallive_0000000000000000',
        testKey: 'sk_notrealtest_0000000000000000'
    },

    // Google Configuration
    google: {
        apiKey: 'NotARealGoogleKey000000000000000'
    },

    // Example configurations (should be ignored)
    example: {
        apiKey: 'YOUR_API_KEY_HERE',
        testKey: 'test_key_1234567890'
    }
};

module.exports = config; 