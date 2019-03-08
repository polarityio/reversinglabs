module.exports = {
  name: 'ReversingLabs',
  acronym: 'RL',
  logging: { level: 'info' },
  entityTypes: ['md5', 'sha1', 'sha256', 'email', 'domain', 'url', 'ipv4'],
  description: 'ReversingLabs integration for real-time file hash lookups',
  styles: ['./styles/reversinglabs.less'],
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
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    // If set to false, the integration will ignore SSL errors.  This will allow the integration to connect
    // to the servers without valid SSL certificates.  Please note that we do NOT recommending setting this
    // to false in a production environment.
    rejectUnauthorized: true
  },
  options: [
    {
      key: 'url',
      name: "ReversingLabs' TitaniumCloud Server URL",
      description: 'TitaniumCloud Server which should include the schema (i.e., https://) and port if required',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'username',
      name: 'Username',
      description: "ReversingLabs' TitaniumCloud API Username",
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Password',
      description: "ReversingLabs' TitaniumCloud password",
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ignoreKnownSamples',
      name: 'Ignore Known Samples',
      description:
        'If checked, the integration will only return results for samples that are marked as "Malicious" or "Suspicious".  Samples marked as "Known" will be ignored.',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupA1000',
      name: 'View data in A1000',
      description:
        'If checked, the integration will create a link that allows users to view information in their A1000 system',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'a1000',
      name: "ReversingLabs' A1000 Server URL",
      description: 'A1000 Server URL which should include the schema (i.e., https://) and port if required',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
        key: 'numHashes',
        name: 'Associated hashes for all other Entity Types',
        description: 'Number of associated hashes to return for all other entity types.',
        default: 10,
        type: 'number',
        userCanEdit: true,
        adminOnly: false
    }
  ]
};
