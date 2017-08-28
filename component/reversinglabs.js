'use strict';
polarity.export = PolarityComponent.extend({

    actions: {
        toggleScanner() {
            this.toggleProperty('isShowingDiv');
        },

        toggleFile() {
            this.toggleProperty('isShowingFile');
        }
    }

});
