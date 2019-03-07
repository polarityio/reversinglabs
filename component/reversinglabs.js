'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  malwarePresence: Ember.computed.alias('details.data.malware_presence'),
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  isShowingScannerDetails: false,
  actions: {
    toggleScanner() {
      this.toggleProperty('isShowingScannerDetails');
    }
  }
});
