module Hyper.Sslify
    ( redirectInsecure
    , isSecure
    , statusMovedPermanently
    , statusTemporaryRedirect
    ) where

import Prelude
import Data.Map as Map
import Control.IxMonad (ibind, (:*>))
import Data.Either (Either(..))
import Data.Foldable (intercalate, null)
import Data.HTTP.Method (Method(..))
import Data.List (List)
import Data.Maybe (Maybe(Just, Nothing))
import Data.StrMap (StrMap, lookup, member)
import Data.Tuple (Tuple(..))
import Hyper.Conn (Conn)
import Hyper.Sslify.Options (Options)
import Hyper.Header (Header)
import Hyper.Middleware (Middleware)
import Hyper.Middleware.Class (getConn, putConn)
import Hyper.Request (class Request, getRequestData)
import Hyper.Response (class Response, HeadersOpen, ResponseEnded, StatusLineOpen, closeHeaders, end, writeHeader, writeStatus)
import Hyper.Status (Status, status, statusBadRequest, statusForbidden, statusFound, statusMethodNotAllowed, statusOK)

type Headers = StrMap String

-- | Redirects or rejects insecure requests according to provided `Options`. This middleware
-- | should be used together with `isSecure` middleware.
redirectInsecure :: ∀ m req res b c
    .  Monad m
    => Request req m
    => Response res m b
    => Options
    →  Middleware
       m
       (Conn req (res StatusLineOpen) {secure :: Boolean | c})
       (Conn req (res ResponseEnded) {secure :: Boolean | c})
       Unit
    →  Middleware
       m
       (Conn req (res StatusLineOpen) {secure :: Boolean | c})
       (Conn req (res ResponseEnded) {secure :: Boolean | c})
       Unit
redirectInsecure opts mw = do
    conn ← getConn
    { headers, method, url } ← getRequestData
    case method of
        Right customMethod → reject
        Left normalMethod → if conn.components.secure then mw else
            case buildSecureUrl opts headers url of
                Nothing → do
                    _ ← putConn conn {components {secure = false}}
                    mw
                Just secureUrl → do
                    _ ← runRedirect opts secureUrl normalMethod
                    _ ← closeHeaders
                    end
    where
        bind = ibind
        reject = do
            _ ← writeStatus statusBadRequest
            _ ← closeHeaders
            end

-- | Puts `secure` property into components, deciding whether a request is secure or not
-- | based on provided `Options`.
isSecure :: ∀ m req res c
    .  Monad m
    => Request req m
    => Options
    →  Middleware
       m
       (Conn req res {secure :: Unit | c})
       (Conn req res {secure :: Boolean | c})
       Unit
isSecure opts = do
    conn ← getConn
    { headers } ← getRequestData
    setSecure (isSecure' opts headers) conn
    where
        setSecure s conn = putConn conn {components {secure = s}}
        bind = ibind

statusMovedPermanently :: Status
statusMovedPermanently = status 301 "Moved permanently"

statusTemporaryRedirect :: Status
statusTemporaryRedirect = status 307 "Temporary redirect"

redirectMethods :: Options -> Map.Map Method Status
redirectMethods opts = Map.fromFoldable $
       map (\m → Tuple m $ redirectStatus opts) opts.redirectMethods
    <> map (\m → Tuple m statusTemporaryRedirect) opts.internalRedirectMethods

runRedirect :: ∀ m req res b c
    .  Monad m
    => Request req m
    => Response res m b
    => Options
    →  String
    →  Method
    →  Middleware
       m
       (Conn req (res StatusLineOpen) c)
       (Conn req (res HeadersOpen) c)
       Unit
runRedirect opts url method = case Map.lookup method statusMethodMap of
    Just status → redirect url status
    Nothing → do
        _ ← writeStatus case method of
            OPTIONS → statusOK
            _ → disallowStatus opts
        case allowHeader $ Map.keys statusMethodMap of
            Nothing → pure unit
            Just allowHeader' → writeHeader allowHeader'
    where
        bind = ibind
        statusMethodMap =  redirectMethods opts

redirect :: ∀ m req res b c
    .  Monad m
    => Response res m b
    => String
    →  Status
    →  Middleware
       m
       (Conn req (res StatusLineOpen) c)
       (Conn req (res HeadersOpen) c)
       Unit
redirect url status = writeStatus status :*> writeHeader (Tuple "Location" url)

redirectStatus :: Options -> Status
redirectStatus opts = if opts.permanent
    then statusMovedPermanently
    else statusFound

disallowStatus :: Options -> Status
disallowStatus opts = if opts.specCompliantDisallow
    then statusMethodNotAllowed
    else statusForbidden

allowHeader :: List Method -> Maybe Header
allowHeader methods = if null methods
    then Nothing
    else Just $ Tuple "Allow" $ intercalate ", " $ map show methods

isSecure' :: Options -> Headers -> Boolean
isSecure' opts headers = hasCustomHeaders opts headers

hasCustomHeaders :: Options -> Headers -> Boolean
hasCustomHeaders opts headers = hasProtoHeader opts headers
                             || hasAzureHeader opts headers

hasProtoHeader :: Options -> Headers -> Boolean
hasProtoHeader opts headers = opts.trustProtoHeader
    && lookup "x-forwarded-proto" headers == Just "https"

hasAzureHeader :: Options -> Headers -> Boolean
hasAzureHeader opts headers = opts.trustAzureHeader
    && member "x-arr-ssl" headers

buildSecureUrl :: Options -> Headers -> String -> Maybe String
buildSecureUrl opts headers url = do
    host <- maybeHost opts headers
    pure $ "https://"
        <> host
        <> port opts
        <> path opts url

maybeHost :: Options → Headers → Maybe String
maybeHost opts headers = case opts.hostname of
    Nothing → lookup "Host" headers
    Just hostname → Just hostname

path :: Options → String → String
path opts url = if opts.ignoreUrl then "" else url

port :: Options → String
port opts = if opts.skipDefaultPort && opts.port == 443
    then ""
    else ":" <> show opts.port