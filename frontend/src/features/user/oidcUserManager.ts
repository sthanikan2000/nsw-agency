import { UserManager, WebStorageStateStore } from 'oidc-client-ts'
import { getEnv, getRequiredEnv } from '@/runtimeConfig'

const rawScopes = getEnv('VITE_IDP_SCOPES')
const scope = rawScopes
  ? rawScopes
      .split(',')
      .map((s) => s.trim())
      .join(' ')
  : 'openid profile email ou'

// RFC 8707 resource indicator: names the resource server this access token is for.
// Required on the authorization request; its identifier becomes the token's `aud`.
const idpResource = getRequiredEnv('VITE_IDP_RESOURCE')

export const userManager = new UserManager({
  authority: getRequiredEnv('VITE_IDP_BASE_URL'),
  client_id: getRequiredEnv('VITE_IDP_CLIENT_ID'),
  redirect_uri: getEnv('VITE_APP_URL') ?? window.location.origin,
  post_logout_redirect_uri: getEnv('VITE_APP_URL') ?? window.location.origin,
  scope,
  extraQueryParams: { resource: idpResource },
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  automaticSilentRenew: true,
})
