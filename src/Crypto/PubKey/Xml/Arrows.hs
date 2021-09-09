{-|
Description: Arrow interface for signing and verifying XML documents
-}

module Crypto.PubKey.Xml.Arrows where

import qualified Crypto.PubKey.Xml as X
import Crypto.PubKey.Xml.Errors

import Text.XML.HXT.Core
import Data.X509

-- | Filters out XML if key validation fails
isSigned :: (ArrowIOIf a) => PubKey -> a XmlTree XmlTree
isSigned key = isIOA $ \ xml -> throwXmlError $ X.verifyXml xml key

-- | Filters out XML if key validation fails
isSignedPem :: (ArrowIOIf a) => FilePath -> a XmlTree XmlTree
isSignedPem pem = isIOA $ \xml -> throwXmlError $ X.verifyXmlPem xml pem
