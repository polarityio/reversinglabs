module.exports = {
    name: 'ReversingLabs',
    acronym: 'RL',
    logging: {level: 'debug'},
    entityTypes: ['hash'],
    description: 'ReversingLabs integration for real-time file hash lookups',
    styles: [
        './styles/reversinglabs.less'
    ],
    block: {
        component: {
            file: './component/reversinglabs.js'
        },
        template: {
            file: './template/reversinglabs.hbs'
        }
    },
    request: {
        // Provide the path to your certFile. Leave an empty string to ignore this option.
        // Relative paths are relative to the VT integration's root directory
        cert: '',
        // Provide the path to your private key. Leave an empty string to ignore this option.
        // Relative paths are relative to the VT integration's root directory
        key: '',
        // Provide the key passphrase if required.  Leave an empty string to ignore this option.
        // Relative paths are relative to the VT integration's root directory
        passphrase: '',
        // Provide the Certificate Authority. Leave an empty string to ignore this option.
        // Relative paths are relative to the VT integration's root directory
        ca: '',
        // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
        // the url parameter (by embedding the auth info in the uri)
        proxy: ''
    },
    options: [
        {
            key: 'url',
            name: 'titaniumCloud Server',
            description: 'TitaniumCloud Server, do not include https://',
            default: '',
            type: 'text',
            userCanEdit: false,
            adminOnly: false
        },
        {
            key: 'username',
            name: 'Username',
            description: 'ReversingLabs API Username',
            default: '',
            type: 'text',
            userCanEdit: false,
            adminOnly: false
        },
        {
            key: 'password',
            name: 'Password',
            description: 'Reversing Labs password',
            default: '',
            type: 'password',
            userCanEdit: false,
            adminOnly: false
        },        {
            key: 'lookupSha256',
            name: 'Lookup SHA256 Hashes',
            description: 'If checked, the integration will lookup SHA256 Hashes',
            default: true,
            type: 'boolean',
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: 'lookupMd5',
            name: 'Lookup MD5 Hashes',
            description: 'If checked, the integration will lookup MD5 Hashes',
            default: true,
            type: 'boolean',
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: 'lookupSha1',
            name: 'Lookup SHA 1 hashes',
            description: 'If checked, the integration will lookup SHA1 Hashes',
            default: true,
            type: 'boolean',
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: 'lookupA1000',
            name: 'View data in A1000',
            description: 'If checked, the integration will create a link that allows users to view information in their A1000 system',
            default: true,
            type: 'boolean',
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: 'a1000',
            name: 'A1000 Server',
            description: 'A1000 Server, do not include the https://',
            default: true,
            type: 'text',
            userCanEdit: true,
            adminOnly: false
        }
    ]
};