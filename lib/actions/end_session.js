'use strict';

const _ = require('lodash');
const crypto = require('crypto');
const compose = require('koa-compose');
const debug = require('debug')('account:end_session'); // Import debug with a namespace

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');

const rejectDupes = require('../shared/check_dupes');
const bodyParser = require('../shared/conditional_body');
const paramsMiddleware = require('../shared/get_params');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function endSessionAction(provider) {
  const STATES = new RegExp(`${provider.cookieName('state')}\\.(\\S+)=`, 'g');

  const loadClient = function* loadClient(clientId) {
    debug(`Loading client with clientId: ${clientId}`); // Debug client loading
    const client = yield provider.Client.find(clientId);

    this.assert(client, new errors.InvalidClientError('unrecognized azp or aud claims'));
    debug(`Client loaded successfully: ${clientId}`); // Debug successful client load

    return client;
  };

  return {
    get: compose([
      paramsMiddleware(['id_token_hint', 'post_logout_redirect_uri', 'state']),

      rejectDupes,

      function* endSessionChecks(next) {
        const params = this.oidc.params;
        debug('Starting endSessionChecks', params); // Debug incoming parameters

        if (params.id_token_hint) {
          let client;

          const clientId = (() => {
            try {
              const jot = JWT.decode(params.id_token_hint);
              return jot.payload.azp || jot.payload.aud;
            } catch (err) {
              debug('Error decoding id_token_hint:', err.message);
              return this.throw(new errors.InvalidRequestError(
                `could not decode id_token_hint (${err.message})`));
            }
          })();

          try {
            client = yield loadClient.call(this, clientId);
            yield provider.IdToken.validate(params.id_token_hint, client);
            debug('id_token_hint validated successfully');
          } catch (err) {
            debug('Error validating id_token_hint:', err.message);
            this.throw(new errors.InvalidRequestError(
              `could not validate id_token_hint (${err.message})`));
          }

          if (params.post_logout_redirect_uri) {
            this.assert(client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri),
              new errors.InvalidRequestError('post_logout_redirect_uri not registered'));
            debug('post_logout_redirect_uri validated successfully');
          }

          this.oidc.client = client;
        } else {
          params.post_logout_redirect_uri = undefined;
        }

        yield next;
      },

      function* renderLogout(next) {
        debug('Rendering logout page');
        const secret = crypto.randomBytes(24).toString('hex');

        this.oidc.session.logout = {
          secret,
          clientId: this.oidc.client ? this.oidc.client.clientId : undefined,
          state: this.oidc.params.state,
          postLogoutRedirectUri: this.oidc.params.post_logout_redirect_uri ||
            instance(provider).configuration('postLogoutRedirectUri'),
          state: this.oidc.params.state,
        };

        this.type = 'html';
        this.status = 200;

        const formhtml = `<form id="op.logoutForm" method="post" action="${this.oidc.urlFor('end_session')}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
        instance(provider).configuration('logoutSource').call(this, formhtml);

        debug('Logout page rendered successfully');
        yield next;
      },
    ]),

    post: compose([
      parseBody,

      paramsMiddleware(['xsrf', 'logout']),

      rejectDupes,

      function* checkLogoutToken(next) {
        debug('Checking logout token');
        this.assert(this.oidc.session.logout, new errors.InvalidRequestError(
          'could not find logout details'));
        this.assert(this.oidc.session.logout.secret === this.oidc.params.xsrf,
          new errors.InvalidRequestError('xsrf token invalid'));
        debug('Logout token validated successfully');
        yield next;
      },

      function* endSession(next) {
        debug('Ending session');
        const params = this.oidc.session.logout;

        const opts = _.omit(instance(provider).configuration('cookies.long'), 'maxAge', 'expires');

        if (this.oidc.params.logout) {
          if (instance(provider).configuration('features.backchannelLogout')) {
            try {
              const Client = provider.Client;
              const clientIds = Object.keys(this.oidc.session.authorizations);
              const logouts = clientIds.map(visitedClientId => Client.find(visitedClientId)
                .then((visitedClient) => {
                  if (visitedClient && visitedClient.backchannelLogoutUri) {
                    return visitedClient.backchannelLogout(this.oidc.session.accountId(),
                      this.oidc.session.sidFor(visitedClient.clientId));
                  }
                  return undefined;
                }));

              yield logouts;
              debug('Backchannel logout completed');
            } catch (err) {
              debug('Error during backchannel logout:', err.message);
            }
          }

          this.provider.emit('end_session.success', this.oidc.session.accountId(), this);
          yield this.oidc.session.destroy();
          debug('Session destroyed successfully');

          const cookies = this.get('cookie').match(STATES);
          if (cookies) {
            cookies.forEach((val) => {
              const name = val.slice(0, -1);
              if (!name.endsWith('.sig')) this.cookies.set(val.slice(0, -1), null, opts);
            });
          }

          this.cookies.set(provider.cookieName('session'), null, opts);
        } else if (params.clientId) {
          delete this.oidc.session.authorizations[params.clientId];
          this.cookies.set(`${provider.cookieName('state')}.${params.clientId}`, null, opts);
        }

        const uri = redirectUri(params.postLogoutRedirectUri,
          params.state != null ? { state: params.state } : undefined); // eslint-disable-line eqeqeq

        debug('Redirecting to post logout URI:', uri);
        this.redirect(uri);

        yield next;
      },
    ]),
  };
};
