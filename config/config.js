module.exports = {
    "name": "ReversingLabs",
    "acronym":"RL",
    "logging": { level: 'info'},
    "entityTypes": ['hash'],
    "description": "ReversingLabs integration",
    "styles":[
        "./styles/reversinglabs.less"
    ],
    "block": {
        "component": {
            "file": "./component/reversinglabs.js"
        },
        "template": {
            "file": "./template/reversinglabs.hbs"
        }
    },
    "options":[
        {
            "key"         : "url",
            "name"        : "Server",
            "description" : "TitaniumCloud Server",
            "default"     : "",
            "type"        : "text",
            "userCanEdit" : false,
            "adminOnly"    : false
        },
        {
            "key"         : "username",
            "name"        : "Username",
            "description" : "ReversingLabs API Username",
            "default"     : "",
            "type"        : "text",
            "userCanEdit" : false,
            "adminOnly"    : false
        },
        {
            "key"         : "password",
            "name"        : "Password",
            "description" : "Reversing Labs password",
            "default"     : "",
            "type"        : "password",
            "userCanEdit" : false,
            "adminOnly"    : false
        },
        {
            "key": "lookupMaleware",
            "name": "Lookup Malware File Information",
            "description": "If checked, the integration will lookup File information on Maleware",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupSha256",
            "name": "Lookup SHA256 Hashes",
            "description": "If checked, the integration will lookup SHA256 Hashes",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupMd5",
            "name": "Lookup MD5 Hashes",
            "description": "If checked, the integration will lookup MD5 Hashes",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key": "lookupSha1",
            "name": "Lookup SHA 1 hashes",
            "description": "If checked, the integration will lookup SHA1 Hashes",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        }
    ]
};