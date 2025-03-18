'use strict';

const debug = require('debug')('account:session'); // Import debug with a namespace

module.exports = function getSessionHandler(provider) {
  return function* sessionHandler(next) {
    try {
      debug('Fetching session for the request');
      this.oidc.session = yield provider.Session.get(this);
      debug('Session fetched successfully:', this.oidc.session);

      yield next;

      if (this.oidc.session.transient) {
        debug('Processing transient session cookies');
        this.response.get('set-cookie').forEach((cookie, index, ary) => {
          if (
            cookie.startsWith(provider.cookieName('session')) &&
            !cookie.includes('expires=Thu, 01 Jan 1970')
          ) {
            ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, ''); // eslint-disable-line no-param-reassign
            debug('Updated transient session cookie:', ary[index]);
          }
        });
      }

      debug('Saving session');
      yield this.oidc.session.save();
      debug('Session saved successfully');
    } catch (err) {
      debug('Error in sessionHandler:', err.message);
      throw err;
    }
  };
};
