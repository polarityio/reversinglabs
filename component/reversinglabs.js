'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  malwarePresence: Ember.computed.alias('details.malware_presence'),
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  isShowingScannerDetails: false,
  statusClass: Ember.computed('malwarePresence.status', function() {
    let status = this.get('malwarePresence.status').toLowerCase();
    if (status === 'malicious') {
      return 'status-malicious';
    }
    if (status === 'suspicious') {
      return 'status-suspicious';
    }
    if (status === 'known') {
      return 'status-known';
    }
    return '';
  }),
  threatLevelHuman: Ember.computed('malwarePresence.threat_level', function() {
    let threatLevel = this.get('malwarePresence.threat_level');
    if (threatLevel === 1) {
      return 'low';
    }
    if (threatLevel === 2 || threatLevel === 3) {
      return 'medium';
    }
    if (threatLevel === 4 || threatLevel === 5) {
      return 'high';
    }

    return 'none';
  }),
  trustFactorHuman: Ember.computed('malwarePresence.trust_factor', function() {
    let trustFactor = this.get('malwarePresence.trust_factor');
    if (trustFactor === 1) {
      return 'high';
    }
    if (trustFactor === 2 || trustFactor === 3) {
      return 'medium';
    }
    if (trustFactor === 4 || trustFactor === 5) {
      return 'low';
    }

    return 'none';
  }),
  actions: {
    toggleScanner() {
      this.toggleProperty('isShowingScannerDetails');
    }
  }
});
