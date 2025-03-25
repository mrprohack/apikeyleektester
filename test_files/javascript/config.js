// API Configuration
const config = {
    // AWS Configuration
    aws: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    },

    // GitHub Configuration
    github: {
        token: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
    },

    // Stripe Configuration
    stripe: {
        liveKey: 'sk_live_1234567890abcdefghijklmn',
        testKey: 'sk_test_1234567890abcdefghijklmn'
    },

    // Google Configuration
    google: {
        apiKey: 'AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz'
    },

    // Example configurations (should be ignored)
    example: {
        apiKey: 'YOUR_API_KEY_HERE',
        testKey: 'test_key_1234567890'
    }
};

module.exports = config; 