{-# LANGUAGE TypeSynonymInstances #-}

{-|
Description: Error Types
-}

module Crypto.PubKey.Xml.Errors where

import Control.Exception
import Data.Either

data XmlVerifyError = XmlSecInitFailed -- -2
                    | XmlSecIncomp     -- -3
                    | XmlSecCryptoFail -- -4
                    | CryptoInitFailed -- -5
                    | XmlCryptoFailed  -- -6
                    | XmlParseFail     -- -7
                    | XmlNoStartNode   -- -8
                    | XmlSigCreateFail -- -9
                    | XmlPemLoadFail   -- -10
                    | XmlPemNameFail   -- -11
                    | VeryifyFail      -- -12

instance Show XmlVerifyError where
  show XmlSecInitFailed = "xmlsec initialization failed"
  show XmlSecIncomp     = "loaded xmlsec library version is not compatible"
  show XmlSecCryptoFail = "unable to load default xmlsec-crypto library"
  show CryptoInitFailed = "crypto initialization failed"
  show XmlCryptoFailed  = "xmlsec-crypto initialization failed"
  show XmlParseFail     = "unable to parse file"
  show XmlNoStartNode   = "start node not found"
  show XmlSigCreateFail = "failed to create signature context"
  show XmlPemLoadFail   = "failed to load public pem key"
  show XmlPemNameFail   = "failed to set key name for key"
  show VeryifyFail      = "signature verify fail"

instance Exception XmlVerifyError

throwXmlError :: IO (Either XmlVerifyError a) -> IO a
throwXmlError res = res >>= either throwIO return
