module.exports = {
  name: 'ReversingLabs',
  acronym: 'RL',
  defaultColor: 'light-pink',
  logging: { level: 'info' },
  entityTypes: ['MD5', 'SHA1', 'SHA256'],
  /**
   * The ReversingLabs integration also supports lookups on email, domain, url and ipv4.  These lookups can be noisey
   * however and are turned off by default.  If you would like to enable these lookups please add in the required
   * entity types to the array above or comment out the line above and uncomment the line below.
   */
  //entityTypes: ['hash', 'email', 'domain', 'ipv4', 'url'],
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
    proxy: ''
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
      adminOnly: true
    },
    {
      key: 'password',
      name: 'Password',
      description: "ReversingLabs' TitaniumCloud password",
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
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
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'a1000',
      name: "ReversingLabs' A1000 Server URL",
      description: 'A1000 Server URL which should include the schema (i.e., https://) and port if required',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    }
    // {
    //   key: 'numHashes',
    //   name: 'Associated hashes for non-hash entity types',
    //   description: 'Number of associated hashes to return for non-hash entity types (e.g., IPv4, or email).',
    //   default: 10,
    //   type: 'number',
    //   userCanEdit: true,
    //   adminOnly: false
    // }
    // {
    //   key: 'blocklist',
    //   name: 'Ignored Entities',
    //   description: 'Comma delimited list of domains that you do not want to lookup.',
    //   default: '',
    //   type: 'text',
    //   userCanEdit: true,
    //   adminOnly: false
    // },
    // {
    //   key: 'domainBlocklistRegex',
    //   name: 'Ignored Domain Regex',
    //   description:
    //     'Domains that match the given regex will not be looked up.',
    //   default: '',
    //   type: 'text',
    //   userCanEdit: true,
    //   adminOnly: false
    // },
    // {
    //   key: 'ipBlocklistRegex',
    //   name: 'Ignored IP Regex',
    //   description: 'IPs that match the given regex will not be looked up.',
    //   default: '',
    //   type: 'text',
    //   userCanEdit: true,
    //   adminOnly: false
    // }
  ]
};
