module Hyper.Sslify.SslifySpec where

import Prelude
import Control.IxMonad (ibind)
import Control.Monad.Aff.Class (class MonadAff)
import Control.Monad.Eff.Class (liftEff)
import Data.Either (Either(..))
import Data.HTTP.Method (CustomMethod, Method(..))
import Data.Maybe (Maybe(..))
import Data.StrMap (StrMap, singleton)
import Data.Tuple (Tuple(..))
import Hyper.Sslify (isSecure, redirectInsecure, statusMovedPermanently, statusTemporaryRedirect)
import Hyper.Sslify.Options (Options, defaultOptions)
import Hyper.Middleware (evalMiddleware)
import Hyper.Node.Test (TestResponseBody)
import Hyper.Response (ResponseEnded, closeHeaders, respond, writeStatus)
import Hyper.Status (statusForbidden, statusFound, statusMethodNotAllowed, statusOK)
import Hyper.Test.TestServer (TestRequest(TestRequest), TestResponse(TestResponse), defaultRequest, testHeaders, testServer, testStatus)
import Node.Buffer (BUFFER, fromString)
import Node.Encoding (Encoding(..))
import Test.Spec (Spec, describe, it)
import Test.Spec.Assertions (shouldEqual)

spec :: ∀ e. Spec (buffer :: BUFFER | e) Unit
spec = do
    describe "Hyper.Sslify.isSecure" do
        let protoOpts = opts {trustProtoHeader = true}
        let azureOpts = opts {trustAzureHeader = true}

        it "should mark as insecure" do
            response ← runIsHttps' opts
            response.components.secure `shouldEqual` false
        it "should mark insecure with insecure proto header" do
            let header = singleton "x-forwarded-proto" "http"
            response ← runIsHttps protoOpts (defaultHeaders <> header)
            response.components.secure `shouldEqual` false
        it "should mark secure with secure proto header" do
            let header = singleton "x-forwarded-proto" "https"
            response ← runIsHttps protoOpts (defaultHeaders <> header)
            response.components.secure `shouldEqual` true
        it "should mark secure with secure with x-arr-ssl header" do
            let header = singleton "x-arr-ssl" "foo"
            response ← runIsHttps azureOpts (defaultHeaders <> header)
            response.components.secure `shouldEqual` true
        it "should mark insecure with insecure header" do
            let header = singleton "x-forwarded-proto" "http"
                 <> singleton "x-arr-ssl" "foo"
            response ← runIsHttps protoOpts (defaultHeaders <> header)
            response.components.secure `shouldEqual` false
    describe "Hyper.Sslify.redirectInsecure" do
        it "should redirect when insecure" do
            response ← re' false
            assertRedirect' response "https://www.example.com"
        it "should not redirect when secure" do
            response ← re' true
            assertNoRedirect response
        it "should redirect to proper path" do
            let req' = req {url = "/path"}
            response ← re req' opts false
            assertRedirect' response "https://www.example.com/path"
        it "should ignore path" do
            let req' = req {url = "/path"}
            let opts' = opts { ignoreUrl = true }
            response ← re req' opts' false
            assertRedirect' response "https://www.example.com"
        it "should use custom hostname" do
            let opts' = opts { hostname = Just "foo" }
            response ← re req opts' false
            assertRedirect' response "https://foo"
        it "should use custom port" do
            let opts' = opts { port = 123 }
            response ← re req opts' false
            assertRedirect' response "https://www.example.com:123"
        it "should not skip default port" do
            let opts' = opts { skipDefaultPort = false }
            response ← re req opts' false
            assertRedirect' response "https://www.example.com:443"
        it "should redirect permanently" do
            let opts' = opts { permanent = true }
            response ← re req opts' false
            assertRedirect statusMovedPermanently response "https://www.example.com"
        it "should reject POST" do
            let req' = req { method = Left POST }
            response ← re req' opts false

            let status = testStatus response
            status `shouldEqual` Just statusForbidden

            let headers = testHeaders response
            headers `shouldEqual` [Tuple "Allow" "GET, HEAD"]
        it "should reject POST with spec compliant status" do
            let req' = req { method = Left POST }
            let opts' = opts { specCompliantDisallow = true }
            response ← re req' opts' false

            let status = testStatus response
            status `shouldEqual` Just statusMethodNotAllowed

            let headers = testHeaders response
            headers `shouldEqual` [Tuple "Allow" "GET, HEAD"]
        it "should do an internal redirect for POST" do
            let req' = req { method = Left POST }
            let opts' = opts { internalRedirectMethods = [POST] }
            response ← re req' opts' false

            let headers = testHeaders response
            let status = testStatus response

            headers `shouldEqual` [Tuple "Location" "https://www.example.com"]
            status `shouldEqual` Just statusTemporaryRedirect
        it "should reject HEAD" do
            let req' = req { method = Left HEAD }
            let opts' = opts { redirectMethods = [GET] }
            response ← re req' opts' false

            let status = testStatus response
            status `shouldEqual` Just statusForbidden

            let headers = testHeaders response
            headers `shouldEqual` [Tuple "Allow" "GET"]
        it "should not write empty Allow header" do
            let opts' = opts { redirectMethods = [] }
            response ← re req opts' false

            let headers = testHeaders response
            headers `shouldEqual` []

    where
        hds = defaultHeaders
        opts = defaultOptions
        req = defaultRequest { headers = hds }

        runIsHttps opts' hd =
            { request: TestRequest (req {headers = hd })
            , response: {}
            , components: { secure: unit }
            }
            # evalMiddleware (isSecure opts')
        runIsHttps' opts' = runIsHttps opts' defaultHeaders
        assertNoRedirect response = do
            let headers = testHeaders response
            let status = testStatus response
            headers `shouldEqual` []
            status `shouldEqual` Just statusOK

        assertRedirect status response expectedUrl = do
            let headers = testHeaders response
            let status' = testStatus response
            headers `shouldEqual` [Tuple "Location" expectedUrl]
            status' `shouldEqual` Just status

        assertRedirect' = assertRedirect statusFound
        re' = re req opts



re :: ∀ m e
    .  MonadAff (buffer :: BUFFER | e) m
    => {url :: String, headers :: StrMap String, method :: Either Method CustomMethod, body :: String}
     → Options
     → Boolean
     → m (TestResponse TestResponseBody ResponseEnded)
re req opts secure =
    { request: TestRequest req
    , response: TestResponse Nothing [] []
    , components: { secure: secure }
    }
    # evalMiddleware (redirectInsecure opts echo)
    # testServer
    where
        echo = do
            body ← liftEff (fromString "Hello World" UTF8)
            _ ← writeStatus statusOK
            _ ← closeHeaders
            respond body
            where bind = ibind

defaultHeaders :: StrMap String
defaultHeaders = singleton "Host" "www.example.com"

