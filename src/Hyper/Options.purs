module Hyper.Sslify.Options
    ( defaultOptions
    , Options
    ) where

import Data.HTTP.Method (Method(..))
import Data.Maybe (Maybe(..))

-- | Options that are used for both `isSecure` and `redirectInsecure`.
-- | - `trustProtoHeader`: trust "x-forwarded-proto" header from Heroku or from other cloud services.
-- | - `trustAzureHeader`: trust Azure's x-arr-ssl header
-- | - `port`: HTTPS port
-- | - `hostname`: host name for redirect; when `Nothing`, it redirects to same host.
-- | - `ignoreUrl`: ignore request url, redirect all request to root.
-- | - `permanent`: use HTTP 301 instead of HTTP 302 for redirection
-- | - `skipDefaultPort`: when false, adds ":443" port to the redirection URL
-- | - `redirectMethods`: allowed HTTP methods for redirection; if method is not allowed, responds with HTTP 40x status
-- | - `internalRedirectMethods`: allowed HTTPS methods for internal redirection, using HTTP 307 status code; can be
-- |   used for redirecting methods other than GET and HEAD with the same method.
-- | - `specCompliantDisallow`: if true, rejects disallowed methods with HTTP 403.

type Options =
  { trustProtoHeader :: Boolean
  , trustAzureHeader :: Boolean
  , port :: Int
  , hostname :: Maybe String
  , ignoreUrl :: Boolean
  , permanent :: Boolean
  , skipDefaultPort :: Boolean
  , redirectMethods :: Array Method
  , internalRedirectMethods :: Array Method
  , specCompliantDisallow :: Boolean
  }

defaultOptions :: Options
defaultOptions =
    { trustProtoHeader: false
    , trustAzureHeader: false
    , port: 443
    , hostname: Nothing
    , ignoreUrl: false
    , permanent: false
    , skipDefaultPort: true
    , redirectMethods: [GET, HEAD]
    , internalRedirectMethods: []
    , specCompliantDisallow: false
    }